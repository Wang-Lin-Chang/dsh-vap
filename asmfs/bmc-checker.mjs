#!/usr/bin/env node
// bmc-checker.mjs —— ASM-FS 有界模型检查器（BMC），spec 驱动版
//
// 目标：在抽象模型层面证明/证伪 6 个定理 E-1~E-6。
// 纪律（与立项书一致）：
//   · 零第三方依赖：仅使用 node: 内置模块（fs/path/crypto/url），不 import 任何外部包。
//   · spec 驱动：检查器启动时用 fs 读取 specs/E-1~E-6.json，每个定理的
//     状态机参数、断言目标、预期状态空间大小全部取自对应 spec 的 model 字段；
//     spec 缺失 / 非法 JSON / id 不一致 / 缺 model 字段 => 立即报错退出（禁止空跑自证）。
//   · 抽象状态机：状态 = 五态标记 × 锁(pid,startSec) × exitCode × done 标记 × 事件列表。
//   · 单次 fs 调用 = 原子步：O_EXCL 独占创建、tmp+rename 原子重命名被当作公理
//     （OS 保证，属于代码外的假设，不在内部证明）。
//   · 有界穷举 ≠ 全称证明：每条定理标注有限域边界（N ≤ 4、状态空间有限）。
//   · 反例必须可重放：每个反例附带操作序列，replay() 可重新执行并复现违例。
//
// 状态编码（对应 brief 的抽象状态元组）：
//   state     ∈ { ⊥, running, stopping, orphaned, adopted, done }  —— 由 observe() 优先级唯一推导
//   lock      ∈ { ⊥, (pid, startSec) }                              —— 锁文件内容
//   exitCode  ∈ { ⊥, c }                                            —— 退出码文件内容
//   doneFile  ∈ { 0, 1 }                                            —— done 标记文件
//   events    ∈ [ (seq, e) ]                                        —— 事件日志（事件溯源）

import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const SPECS_DIR = join(HERE, 'specs')
const SPEC_IDS = ['E-1', 'E-2', 'E-3', 'E-4', 'E-5', 'E-6']

// ---------------------------------------------------------------------------
// spec 加载与校验（spec 是验证的唯一参数来源；缺失/损坏即失败）
// ---------------------------------------------------------------------------

function sha256(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

function specPath(id, dir) {
  return join(dir, `${id}.json`)
}

function loadSpecText(id, dir) {
  const p = specPath(id, dir)
  let raw
  try {
    raw = readFileSync(p, 'utf8')
  } catch (e) {
    throw new Error(`[spec 加载失败] 无法读取 ${p}（${e.code || e.message}）。检查器必须以 specs/E-*.json 为唯一参数来源，缺失即中止，禁止硬编码自证。`)
  }
  return raw
}

function parseSpec(id, raw, dir) {
  let obj
  try {
    obj = JSON.parse(raw)
  } catch (e) {
    throw new Error(`[spec 解析失败] ${specPath(id, dir)} 不是合法 JSON：${e.message}`)
  }
  if (obj.id !== id) {
    throw new Error(`[spec 不一致] ${specPath(id, dir)} 声明 id="${obj.id}"，与文件名 "${id}.json" 不符`)
  }
  if (!obj.model || typeof obj.model !== 'object' || Array.isArray(obj.model)) {
    throw new Error(`[spec 缺字段] ${specPath(id, dir)} 缺少 "model" 对象（spec 驱动的验证参数）`)
  }
  if (!obj.title || !obj.boundary) {
    throw new Error(`[spec 缺字段] ${specPath(id, dir)} 缺少 "title" 或 "boundary"`)
  }
  return obj
}

/**
 * loadSpecs(dir)：按文件名顺序 E-1..E-6 读取并校验全部 spec。
 * 返回 { byId: { id: spec }, hashes: { id: sha256(raw) } }。
 * 任一步失败（缺失 / 非法 JSON / id 不符 / 缺 model）都会抛出明确错误。
 */
function loadSpecs(dir = SPECS_DIR) {
  const byId = {}
  const hashes = {}
  for (const id of SPEC_IDS) {
    const raw = loadSpecText(id, dir)
    byId[id] = parseSpec(id, raw, dir)
    hashes[id] = sha256(raw)
  }
  return { byId, hashes }
}

// ---------------------------------------------------------------------------
// 基本工具
// ---------------------------------------------------------------------------

/** 深拷贝 task（状态机对象），避免 BFS 分支间共享引用。 */
function cloneTask(t) {
  return {
    markers: { ...t.markers },
    lock: t.lock === null ? null : { ...t.lock },
    exitCode: t.exitCode,
    events: t.events.map((e) => ({ ...e })),
    doneWins: t.doneWins,
    adoptWins: t.adoptWins,
    lastLiveness: t.lastLiveness,
  }
}

/** 深拷贝 world（进程表，Map<pid,{alive,startSec}>）。 */
function cloneWorld(w) {
  const n = new Map()
  for (const [k, v] of w) n.set(k, { ...v })
  return n
}

/** world 转可序列化对象（按 pid 升序，保证哈希稳定）。 */
function worldToObj(world) {
  const keys = [...world.keys()].sort((a, b) => a - b)
  const o = {}
  for (const k of keys) o[k] = world.get(k)
  return o
}

/** 状态哈希键（task + world + pos + localSeq）。 */
function sysKey(task, world, pos, localSeq) {
  return JSON.stringify([task, worldToObj(world), pos, localSeq])
}

function freshTask() {
  return {
    markers: { done: 0, running: 0, stopping: 0, adopted: 0, orphaned: 0 },
    lock: null,
    exitCode: null,
    events: [],
    doneWins: 0,
    adoptWins: 0,
    lastLiveness: null,
  }
}

function freshWorld() {
  return new Map()
}

// ---------------------------------------------------------------------------
// 抽象状态机：转移（单 fs 调用 = 原子步）
// ---------------------------------------------------------------------------

/**
 * liveness(pid, startSec, world)：三分全函数 alive / dead / pid_reused。
 *   - startSec === null（⊥）：退化为二证据（仅 pid 存活与否），此时永不出 pid_reused。
 *   - startSec 有定义：pid 存活且 startSec 恒等 => alive；pid 不存活 => dead；
 *     pid 存活但 startSec 不匹配 => pid_reused（pid 被复用）。
 */
function liveness(pid, startSec, world) {
  const p = world.get(pid)
  if (startSec === null) {
    // 退化前置条件：锁无 startSec 时只有二证据。
    return p !== undefined && p.alive ? 'alive' : 'dead'
  }
  if (p === undefined || !p.alive) return 'dead'
  if (p.startSec === startSec) return 'alive'
  return 'pid_reused'
}

/** 五态优先级：done > running > stopping > adopted > orphaned（模型固定语义）。 */
const MARKER_PRIORITY = ['done', 'running', 'stopping', 'adopted', 'orphaned']

/**
 * observe(markers)：按优先级返回唯一可观察标签；空集 => 'none'（即 ⊥）。
 * 这是 E-6 的核心：优先级全序保证对任意标记组合输出唯一标签。
 */
function observe(markers) {
  for (const m of MARKER_PRIORITY) {
    if (markers[m]) return m
  }
  return 'none'
}

/**
 * 单步转移。actor = { pid, startSec }；actorIdx 用于 per-actor 本地变量（E-4 朴素版）。
 * op = { op, code?, e? }。返回 { outcome }；outcome 用于记录到反例轨迹。
 */
function step(task, world, localSeq, actorIdx, actor, op) {
  let outcome = null
  switch (op.op) {
    case 'spawn': {
      // 进程登记 + （若锁空闲则）认领锁：running。
      world.set(actor.pid, { alive: true, startSec: actor.startSec })
      if (task.lock === null) {
        task.lock = { pid: actor.pid, startSec: actor.startSec }
        task.markers.running = 1
        outcome = 'claimed'
      } else {
        outcome = 'lock-held'
      }
      break
    }
    case 'stop': {
      // 持有者请求停止：running -> stopping。
      if (task.lock !== null && task.lock.pid === actor.pid && task.markers.running === 1) {
        task.markers.running = 0
        task.markers.stopping = 1
        outcome = 'stopping'
      } else {
        outcome = 'not-owner'
      }
      break
    }
    case 'crash': {
      // 进程崩溃：world 标记死亡；锁残留 => orphaned。
      const p = world.get(actor.pid)
      if (p !== undefined) p.alive = false
      if (task.lock !== null && task.lock.pid === actor.pid) {
        task.markers.running = 0
        task.markers.stopping = 0
        task.markers.orphaned = 1
        outcome = 'orphaned'
      } else {
        outcome = 'crashed'
      }
      break
    }
    case 'adopt': {
      // 三证据收养：liveness 三分；仅 dead 时允许 O_EXCL 认领；pid_reused/alive 均拒绝。
      if (task.lock === null) {
        outcome = 'no-lock'
        break
      }
      const lv = liveness(task.lock.pid, task.lock.startSec, world)
      task.lastLiveness = lv
      if (lv === 'alive') {
        outcome = 'owner-alive'
      } else if (lv === 'pid_reused') {
        outcome = 'reject'
      } else {
        // dead：O_EXCL 认领，恰一赢家。
        if (task.markers.adopted === 0 && task.markers.done === 0) {
          task.markers.orphaned = 0
          task.markers.adopted = 1
          task.lock = { pid: actor.pid, startSec: actor.startSec }
          task.adoptWins += 1
          outcome = 'win'
        } else {
          outcome = 'lose'
        }
      }
      break
    }
    case 'finalize': {
      // O_EXCL done 文件：恰一赢家；其余幂等 no-op。
      if (task.markers.done === 0) {
        task.markers.done = 1
        task.markers.running = 0
        task.markers.stopping = 0
        task.markers.adopted = 0
        task.markers.orphaned = 0
        task.exitCode = op.code
        task.doneWins += 1
        outcome = 'win'
      } else {
        outcome = 'lose'
      }
      break
    }
    case 'readSeq': {
      // E-4 朴素版（证伪对象）：seq = events.length + 1，读到本地变量，两步非原子。
      localSeq[actorIdx] = task.events.length + 1
      outcome = { seq: localSeq[actorIdx] }
      break
    }
    case 'writeEvent': {
      // E-4 朴素版：用本地 seq 追加（可与其他写者撞号）。
      task.events.push({ seq: localSeq[actorIdx], e: op.e })
      outcome = { seq: localSeq[actorIdx] }
      break
    }
    case 'event': {
      // E-4 修复版：单步原子追加（O_EXCL 或单追加日志），seq 单调唯一。
      const seq = task.events.length + 1
      task.events.push({ seq, e: op.e })
      outcome = { seq }
      break
    }
    case 'read': {
      outcome = observe(task.markers)
      break
    }
    default: {
      throw new Error(`未知操作: ${op.op}`)
    }
  }
  return { outcome }
}

// ---------------------------------------------------------------------------
// 穷举引擎：全交错 BFS（按状态去重 + 父指针回溯）
// ---------------------------------------------------------------------------

/**
 * search({ actors, initial, check, maxNodes })
 *   actors : [{ pid, startSec, script: [op,...] }]
 *   initial: { task, world }
 *   check  : (task, world, pos, isTerminal) => null | reason  （null = 该节点满足断言）
 * 返回 { found, counterexample, nodes, interleavings }
 *   counterexample = { trace: [...], finalTask, reason } 或 null
 *
 * BFS 按 (task, world, pos, localSeq) 去重。对安全性断言这是完备的：任何可违例状态都
 * 可由某条交错到达，父指针给出最短反例路径；去重只合并了等价状态，不丢路径。
 */
function search({ actors, initial, check, maxNodes = 2_000_000 }) {
  const N = actors.length
  const startPos = new Array(N).fill(0)
  const startLocalSeq = new Array(N).fill(null)

  const startTask = cloneTask(initial.task)
  const startWorld = cloneWorld(initial.world)

  const isTerm = (pos) => pos.every((p, i) => p === actors[i].script.length)

  const seen = new Set()
  const queue = []
  let interleavings = 0

  const root = {
    task: startTask,
    world: startWorld,
    pos: startPos,
    localSeq: startLocalSeq,
    parent: null,
    stepDesc: null,
  }
  const rKey = sysKey(startTask, startWorld, startPos, startLocalSeq)
  seen.add(rKey)
  queue.push(root)

  const rootViolation = check(startTask, startWorld, startPos, isTerm(startPos))
  if (rootViolation !== null) {
    return {
      found: true,
      counterexample: { trace: [], finalTask: startTask, finalWorld: startWorld, reason: rootViolation },
      nodes: 1,
      interleavings: 0,
    }
  }

  while (queue.length > 0) {
    const node = queue.shift()
    if (isTerm(node.pos)) {
      interleavings += 1
      continue
    }
    if (seen.size > maxNodes) {
      throw new Error(`状态数超出上限 ${maxNodes}`)
    }
    // 枚举下一个可推进的 actor（每个 actor 最多一步 => 保留 per-actor 程序序）。
    for (let i = 0; i < N; i++) {
      if (node.pos[i] >= actors[i].script.length) continue
      const op = actors[i].script[node.pos[i]]
      const task = cloneTask(node.task)
      const world = cloneWorld(node.world)
      const localSeq = node.localSeq.slice()
      const pos = node.pos.slice()
      const { outcome } = step(task, world, localSeq, i, actors[i], op)
      pos[i] += 1
      const key = sysKey(task, world, pos, localSeq)
      if (seen.has(key)) continue
      seen.add(key)
      const child = {
        task,
        world,
        pos,
        localSeq,
        parent: node,
        stepDesc: { actor: actors[i].pid, op: op.op, code: op.code, e: op.e, outcome },
      }
      const violation = check(task, world, pos, isTerm(pos))
      if (violation !== null) {
        // 回溯构造反例轨迹。
        const trace = []
        let cur = child
        while (cur.parent !== null) {
          trace.unshift(cur.stepDesc)
          cur = cur.parent
        }
        return {
          found: true,
          counterexample: { trace, finalTask: task, finalWorld: world, reason: violation },
          nodes: seen.size,
          interleavings,
        }
      }
      queue.push(child)
    }
  }

  return { found: false, counterexample: null, nodes: seen.size, interleavings }
}

/** 反例重放：从初始态按轨迹重新执行，返回最终态并复检断言。 */
function replay({ actors, initial, trace, check }) {
  const task = cloneTask(initial.task)
  const world = cloneWorld(initial.world)
  const localSeq = new Array(actors.length).fill(null)
  const byPid = new Map(actors.map((a, i) => [a.pid, { a, i }]))
  for (const d of trace) {
    const { a, i } = byPid.get(d.actor)
    step(task, world, localSeq, i, a, { op: d.op, code: d.code, e: d.e })
  }
  const pos = actors.map((a) => a.script.length)
  const violation = check(task, world, pos, true)
  return { finalTask: task, finalWorld: world, reason: violation }
}

// ---------------------------------------------------------------------------
// spec -> 验证输入的构造工具
// ---------------------------------------------------------------------------

/** 把 op 模板实例化到第 i 个 actor：整值 "@i" 替换为数字 i，字符串内 "@i" 替换为文本。 */
function instantiateOp(op, i) {
  const out = {}
  for (const [k, v] of Object.entries(op)) {
    if (v === '@i') out[k] = i
    else if (typeof v === 'string') out[k] = v.replaceAll('@i', String(i))
    else out[k] = v
  }
  return out
}

/** 由 model.actor 构造 N 个 actor（pid/startSec 线性派生，script 逐 actor 实例化）。 */
function buildActors(model, n) {
  const { pidBase, startSecBase, script } = model.actor
  const actors = []
  for (let i = 0; i < n; i++) {
    actors.push({
      pid: pidBase + i,
      startSec: startSecBase + i,
      script: script.map((op) => instantiateOp(op, i)),
    })
  }
  return actors
}

/** 由 model.initial 构造初始 { task, world }。 */
function buildInitial(model) {
  const task = freshTask()
  const world = freshWorld()
  const init = model.initial || {}
  if (init.lock) task.lock = { ...init.lock }
  if (init.markers) Object.assign(task.markers, init.markers)
  for (const w of init.world || []) world.set(w.pid, { alive: w.alive, startSec: w.startSec })
  return { task, world }
}

/** 结果对象骨架：id/title/boundary 均取自 spec（证明 spec 驱动，而非硬编码）。 */
function baseResult(spec) {
  return { id: spec.id, title: spec.title, boundary: spec.boundary }
}

/** 浅比较两个数组（顺序敏感）。 */
function sameArray(a, b) {
  return JSON.stringify(a) === JSON.stringify(b)
}

// ---------------------------------------------------------------------------
// 断言 E-1 ~ E-6（全部由对应 spec 的 model 字段驱动）
// ---------------------------------------------------------------------------

function checkE1(spec) {
  if (spec === undefined) spec = loadSpecs().byId['E-1']
  const m = spec.model
  const evidence = []
  const details = []
  const { doneWinsTarget, requireExitCodeWithDone, requireDoneAtTerminal } = m.assertion
  const expNodes = m.expected.nodes
  const expTerm = m.expected.terminalStates

  for (let k = 0; k < m.nRange.length; k++) {
    const N = m.nRange[k]
    const actors = buildActors(m, N)
    const initial = buildInitial(m)

    const check = (task, _world, _pos, isTerminal) => {
      if (task.doneWins > doneWinsTarget) return `doneWins=${task.doneWins}，超过目标 ${doneWinsTarget}（终态非恰一次）`
      if (requireExitCodeWithDone && task.markers.done === 1 && task.exitCode === null) return 'done 标记存在但无退出码'
      if (isTerminal) {
        if (task.doneWins !== doneWinsTarget) return `终态 doneWins=${task.doneWins}（应为 ${doneWinsTarget}）`
        if (task.exitCode === null) return '终态缺退出码'
        if (requireDoneAtTerminal && task.markers.done !== 1) return '终态缺 done 标记'
      }
      return null
    }

    const r = search({ actors, initial, check })
    const nodeSelfCheck = expNodes ? r.nodes === expNodes[k] : true
    const termSelfCheck = expTerm ? r.interleavings === expTerm[k] : true
    const pass = !r.found && nodeSelfCheck && termSelfCheck
    const reason = r.found
      ? r.counterexample.reason
      : !nodeSelfCheck
        ? `状态空间自检失败：实跑 ${r.nodes} ≠ spec 预期 ${expNodes[k]}`
        : !termSelfCheck
          ? `终态数自检失败：实跑 ${r.interleavings} ≠ spec 预期 ${expTerm[k]}`
          : null
    evidence.push(
      `N=${N}: ${pass ? 'PASS' : 'FAIL ' + reason}（交错数 ${r.interleavings}，去重状态 ${r.nodes}` +
        (expNodes ? `，spec 预期去重状态 ${expNodes[k]}` : '') + `）`
    )
    details.push({ N, pass, interleavings: r.interleavings, nodes: r.nodes, expectedNodes: expNodes ? expNodes[k] : null })
  }

  const ok = details.every((d) => d.pass)
  return {
    ...baseResult(spec),
    status: ok ? 'pass' : 'fail',
    summary: ok
      ? `N=${m.nRange.join('/')} 全部交错穷举下，done 标记恰写 ${doneWinsTarget} 次、退出码单值不覆盖；幂等第二次 finalize 一律 no-op（状态空间自检与 spec 预期 ${expNodes.join('/')} 一致）。`
      : '存在终态违反恰一终态、退出码唯一，或状态空间与 spec 预期不符。',
    evidence,
    counterexample: null,
    details,
  }
}

function checkE2(spec) {
  if (spec === undefined) spec = loadSpecs().byId['E-2']
  const m = spec.model
  const evidence = []
  const details = []
  const { adoptWinsTarget, requireAdoptedWithWin, requireOrphanClearedAtTerminal, requireLockAtTerminal } = m.assertion
  const expNodes = m.expected.nodes
  const expTerm = m.expected.terminalStates

  for (let k = 0; k < m.nRange.length; k++) {
    const N = m.nRange[k]
    const actors = buildActors(m, N)
    const initial = buildInitial(m)

    const check = (task, _world, _pos, isTerminal) => {
      if (task.adoptWins > adoptWinsTarget) return `adoptWins=${task.adoptWins}，收养互斥被破坏（目标 ${adoptWinsTarget}）`
      if (requireAdoptedWithWin && task.adoptWins === adoptWinsTarget && task.markers.adopted !== 1) return '恰一赢家但 adopted 标记缺失'
      if (isTerminal) {
        if (task.adoptWins !== adoptWinsTarget) return `终态 adoptWins=${task.adoptWins}（应为 ${adoptWinsTarget}）`
        if (task.markers.adopted !== 1) return '终态未 adopted'
        if (requireOrphanClearedAtTerminal && task.markers.orphaned !== 0) return '终态 orphaned 与 adopted 并存'
        if (requireLockAtTerminal && task.lock === null) return '终态无锁'
      }
      return null
    }

    const r = search({ actors, initial, check })
    const nodeSelfCheck = expNodes ? r.nodes === expNodes[k] : true
    const termSelfCheck = expTerm ? r.interleavings === expTerm[k] : true
    const pass = !r.found && nodeSelfCheck && termSelfCheck
    const reason = r.found
      ? r.counterexample.reason
      : !nodeSelfCheck
        ? `状态空间自检失败：实跑 ${r.nodes} ≠ spec 预期 ${expNodes[k]}`
        : !termSelfCheck
          ? `终态数自检失败：实跑 ${r.interleavings} ≠ spec 预期 ${expTerm[k]}`
          : null
    evidence.push(
      `N=${N}: ${pass ? 'PASS' : 'FAIL ' + reason}（交错数 ${r.interleavings}，去重状态 ${r.nodes}` +
        (expNodes ? `，spec 预期去重状态 ${expNodes[k]}` : '') + `）`
    )
    details.push({ N, pass, interleavings: r.interleavings, nodes: r.nodes, expectedNodes: expNodes ? expNodes[k] : null })
  }

  const ok = details.every((d) => d.pass)
  return {
    ...baseResult(spec),
    status: ok ? 'pass' : 'fail',
    summary: ok
      ? `N=${m.nRange.join('/')} 全部交错下恰 ${adoptWinsTarget} 个 adopt 胜者（O_EXCL 认领），其余全部 lose；终态 adopted 且锁唯一（状态空间自检与 spec 预期 ${expNodes.join('/')} 一致）。`
      : '存在并发收养多赢家、终态不一致，或状态空间与 spec 预期不符。',
    evidence,
    counterexample: null,
    details,
  }
}

function checkE3(spec) {
  if (spec === undefined) spec = loadSpecs().byId['E-3']
  const m = spec.model
  const evidence = []
  const details = {}

  // —— 第 1 部分：liveness 三分全函数（域全枚举，域与预期例数来自 spec） ——
  const tri = m.trichotomy
  let totalCases = 0
  const cases = []
  let ok1 = true
  const LABELS = ['alive', 'dead', 'pid_reused']
  for (const pid of tri.pids) {
    for (const startSec of tri.startSecs) {
      for (const alive of tri.alives) {
        for (const liveSec of tri.liveSecs) {
          totalCases++
          const world = new Map()
          if (alive) world.set(pid, { alive: true, startSec: liveSec })
          const got = liveness(pid, startSec, world)
          cases.push({ pid, startSec, alive, liveSec, got })
          // 全函数：必须唯一输出三分之一。
          if (!LABELS.includes(got)) ok1 = false
          // 退化前提：startSec=⊥ 永不出 pid_reused。
          if (tri.degenerateNoReused && startSec === null && got === 'pid_reused') ok1 = false
        }
      }
    }
  }
  const caseCountOk = totalCases === tri.expectedCases
  evidence.push(
    `三分全函数域枚举：${totalCases} 例，${ok1 ? '全部唯一且正确' : '存在偏差'}` +
      `；退化前提（startSec=⊥）下永不出 pid_reused` +
      `（spec 预期 ${tri.expectedCases} 例 = ${caseCountOk ? '一致' : `不一致（实跑 ${totalCases}）`}）`
  )
  if (!caseCountOk) ok1 = false

  // —— 第 2 部分：三分支单步收养判定（逐分支从 spec 读取输入态与预期输出） ——
  const branchOk = []
  const branchDetails = []
  for (const b of m.branches) {
    const task = freshTask()
    const world = freshWorld()
    task.lock = { ...b.lock }
    Object.assign(task.markers, b.markers || {})
    for (const w of b.world || []) world.set(w.pid, { alive: w.alive, startSec: w.startSec })

    // 单步 adopt，探针 actor 身份与断言无关（adopt 依据 task.lock 判定）。
    const { outcome } = step(task, world, [null], 0, { pid: 9, startSec: 900 }, { op: 'adopt' })

    const exp = b.expected
    let okBranch = outcome === exp.outcome
    if (task.adoptWins !== exp.adoptWins) okBranch = false
    if (task.lastLiveness !== exp.lastLiveness) okBranch = false
    for (const [mk, mv] of Object.entries(exp.markers || {})) {
      if (task.markers[mk] !== mv) okBranch = false
    }
    branchOk.push(okBranch)
    branchDetails.push({ name: b.name, outcome, adoptWins: task.adoptWins, lastLiveness: task.lastLiveness, ok: okBranch })
    evidence.push(
      `分支 ${b.name}（${b.name === 'alive' ? '存活 => owner-alive 拒绝' : b.name === 'dead' ? '已死 => win 收养' : 'pid 复用 => reject 拒绝收养'}）` +
        `: ${okBranch ? 'PASS' : `FAIL outcome=${outcome} adoptWins=${task.adoptWins} lastLiveness=${task.lastLiveness}（spec 预期 ${exp.outcome}/${exp.adoptWins}/${exp.lastLiveness}）`}`
    )
  }

  // —— 第 3 部分：复用态下 N 并发 adopter 全拒绝（前置与断言来自 spec） ——
  const con = m.concurrent
  const prelude = () => {
    const task = freshTask()
    const world = freshWorld()
    const localSeq = [null]
    for (const p of con.prelude) {
      step(task, world, localSeq, 0, { pid: p.pid, startSec: p.startSec }, { op: p.op })
    }
    return { task, world }
  }
  const a = con.assertion
  let okConcurrent = true
  const concurrentEvidence = []
  for (const N of con.nRange) {
    const initial = prelude()
    const actors = buildActors(con, N)
    const check = (task, _w, _p, isTerminal) => {
      if (task.adoptWins > a.adoptWinsTarget) return `pid_reused 态下出现收养赢家（adoptWins=${task.adoptWins}，目标 ${a.adoptWinsTarget}）`
      if (isTerminal) {
        if (task.lastLiveness !== a.lastLivenessTarget) return `终态 lastLiveness=${task.lastLiveness}（应 ${a.lastLivenessTarget}）`
        if (a.requireOrphanedAtTerminal && task.markers.orphaned !== 1) return '孤儿态被错误清除'
        if (a.requireNotAdoptedAtTerminal && task.markers.adopted !== 0) return '孤儿态被错误收养'
      }
      return null
    }
    const r = search({ actors, initial, check })
    if (r.found) okConcurrent = false
    concurrentEvidence.push(`N=${N}: ${r.found ? 'FAIL ' + r.counterexample.reason : 'PASS（全拒绝，0 赢家）'}（交错数 ${r.interleavings}）`)
  }
  evidence.push(`复用态 N 并发全拒绝：${concurrentEvidence.join('；')}`)

  const ok = ok1 && branchOk.every(Boolean) && okConcurrent
  details.cases = cases
  details.branches = branchDetails
  details.concurrent = { nRange: con.nRange }
  return {
    ...baseResult(spec),
    status: ok ? 'pass' : 'fail',
    summary: ok
      ? `liveness 为三分全函数（${tri.expectedCases} 例域枚举全对，⊥ 退化为二证据）；三分支映射正确（alive=>owner-alive、dead=>win、pid_reused=>reject）；复用态下 N=${con.nRange.join('/')} 并发 adopter 全拒绝。`
      : 'liveness 三分、三分支映射或 pid_reused 拒绝收养存在违反。',
    evidence,
    counterexample: null,
    details,
  }
}

function checkE4(spec) {
  if (spec === undefined) spec = loadSpecs().byId['E-4']
  const m = spec.model
  const evidence = []
  const details = {}

  // —— 第 1 阶段：证伪（朴素模型）—— 必须先输出反例 ——
  const naive = {}
  {
    const N = m.naive.n
    const actors = buildActors(m.naive, N)
    const initial = buildInitial(m.naive)
    const check = (task) => {
      const seqs = task.events.map((e) => e.seq)
      if (new Set(seqs).size !== seqs.length) return `事件 seq 冲突：${JSON.stringify(seqs)}`
      return null
    }
    const r = search({ actors, initial, check })
    if (!r.found) {
      throw new Error('E-4 朴素版应发现 seq 冲突反例（证伪优先），但未发现——模型或 spec 有误')
    }
    // 重放验证。
    const rep = replay({ actors, initial, trace: r.counterexample.trace, check })
    const seqs = rep.finalTask.events.map((e) => e.seq)
    const expectedConflict = m.naive.expectedConflictSeq
    const seqMatches = sameArray(seqs, expectedConflict)
    naive.status = 'fail'
    naive.seqMatches = seqMatches
    naive.counterexample = {
      trace: r.counterexample.trace.map((d) => ({
        actor: d.actor,
        op: d.op,
        e: d.e,
        outcome: d.outcome,
      })),
      finalEvents: rep.finalTask.events,
      reason: r.counterexample.reason,
      replayedReason: rep.reason,
      replayedSeq: seqs,
    }
    evidence.push(`证伪阶段（朴素模型 N=${N}）: 发现反例 —— ${r.counterexample.reason}`)
    evidence.push(`反例可重放：replay 复现 seq=${JSON.stringify(seqs)}，复检=${rep.reason}`)
    evidence.push(
      `反例 seq 自检：实跑 ${JSON.stringify(seqs)} 与 spec 预期 ${JSON.stringify(expectedConflict)} = ${seqMatches ? '一致（PASS）' : '不一致（FAIL）'}`
    )
  }

  // —— 第 2 阶段：修复（单步原子追加）—— 全绿 ——
  const fixed = {}
  {
    let allPass = true
    const expTerm = m.fixed.expectedTerminalStates
    const fixedEvidence = []
    for (let k = 0; k < m.fixed.nRange.length; k++) {
      const N = m.fixed.nRange[k]
      const actors = buildActors(m.fixed, N)
      const initial = buildInitial(m.fixed)
      const check = (task) => {
        const seqs = task.events.map((e) => e.seq)
        if (new Set(seqs).size !== seqs.length) return `事件 seq 冲突：${JSON.stringify(seqs)}`
        return null
      }
      const r = search({ actors, initial, check })
      const termSelfCheck = expTerm ? r.interleavings === expTerm[k] : true
      const pass = !r.found && termSelfCheck
      allPass = allPass && pass
      fixedEvidence.push(
        `修复阶段（单步原子追加 N=${N}）: ${pass ? 'PASS' : 'FAIL'}（交错数 ${r.interleavings}` +
          (expTerm ? `，spec 预期 ${expTerm[k]}` : '') + `）`
      )
    }
    fixed.status = allPass ? 'pass' : 'fail'
    fixed.evidence = fixedEvidence
    evidence.push(...fixedEvidence)
  }

  details.naive = naive
  details.fixed = { status: fixed.status, boundary: spec.boundary }

  const ok = naive.status === 'fail' && naive.seqMatches === true && fixed.status === 'pass'
  return {
    ...baseResult(spec),
    status: ok ? 'pass' : 'fail',
    summary: ok
      ? '证伪优先纪律达成：朴素模型 seq=length+1 两步非原子在并发下 seq 冲突（反例可重放、seq 与 spec 预期一致）；修复为单步原子追加后 N=2/3/4 全绿。'
      : 'E-4 证伪、反例 seq 与 spec 预期不符，或修复阶段未达预期。',
    evidence,
    counterexample: naive.counterexample,
    details,
  }
}

function checkE5(spec) {
  if (spec === undefined) spec = loadSpecs().byId['E-5']
  const m = spec.model
  const evidence = []

  const CAPS = m.caps
  const MODES = m.modes
  const denyOf = m.denyOf
  const asSet = (arr) => new Set(arr)

  // 1) 单调性：mode 升序 => deny 集单调不增（等价 allow 集单调不减）。
  let monotone = true
  const chain = []
  for (let i = 0; i < MODES.length - 1; i++) {
    const m1 = MODES[i]
    const m2 = MODES[i + 1]
    const d1 = asSet(denyOf[m1])
    const d2 = asSet(denyOf[m2])
    const subset = [...d2].every((c) => d1.has(c))
    const strict = subset && d1.size > d2.size
    chain.push({ lower: m1, upper: m2, 'deny(upper)⊆deny(lower)': subset, strict })
    if (!subset || !strict) monotone = false
  }
  evidence.push(
    `保序链：${chain.map((c) => `${c.lower}≤${c.upper}: deny(${c.upper})⊆deny(${c.lower}) = ${c['deny(upper)⊆deny(lower)']}（严格 ${c.strict}）`).join('；')}`
  )

  // 2) 逐原语全枚举：对每对 m1 ≤ m2，凡 m1 允许者 m2 必允许（allow 单调不减）。
  let perCap = true
  for (const c of CAPS) {
    for (let i = 0; i < MODES.length - 1; i++) {
      const m1 = MODES[i]
      const m2 = MODES[i + 1]
      const a1 = asSet(CAPS.filter((x) => !denyOf[m1].includes(x)))
      const a2 = asSet(CAPS.filter((x) => !denyOf[m2].includes(x)))
      if (a1.has(c) && !a2.has(c)) perCap = false
    }
  }
  evidence.push(`逐原语单调性（allow 不减）：${perCap ? 'PASS' : 'FAIL'}`)

  // 3) 嵌入非同构：三个 deny 集两两互异（单射嵌入），且存在非模式的 deny 子集（非满射 => 非同构）。
  const sets = MODES.map((md) => JSON.stringify([...denyOf[md]].sort()))
  const injective = new Set(sets).size === MODES.length
  const aSubset = m.nonSurjectiveWitness
  const notSurjective = !sets.includes(JSON.stringify([...aSubset].sort()))
  evidence.push(`嵌入非满射（非同构）：三 deny 集互异 = ${injective}；存在非模式 deny 子集 ${JSON.stringify(aSubset)} = ${notSurjective}`)

  const ok = monotone && perCap && injective && notSurjective
  return {
    ...baseResult(spec),
    status: ok ? 'pass' : 'fail',
    summary: ok
      ? `${MODES.join(' ≤ ')} 下 deny 集严格单调不增（deny(read-only) ⊇ deny(workspace-write) ⊇ deny(danger-full-access)）；嵌入单射但非满射（非同构）。`
      : '能力格保序或嵌入性质存在违反（deny 集来自 spec，改坏 spec 的 denyOf 即触发）。',
    evidence,
    counterexample: null,
    details: { denyOf, chain },
  }
}

function checkE6(spec) {
  if (spec === undefined) spec = loadSpecs().byId['E-6']
  const m = spec.model
  const evidence = []

  // spec 自检：spec 声明的优先级必须等于模型固定优先级（否则 FAIL）。
  const declaredPriority = m.priority
  const priorityOk = sameArray(declaredPriority, MARKER_PRIORITY)
  evidence.push(
    `优先级自检：spec 声明 ${JSON.stringify(declaredPriority)} 与模型优先级 ${JSON.stringify(MARKER_PRIORITY)} 一致 = ${priorityOk ? 'PASS' : 'FAIL'}`
  )

  // 全枚举：所有 marker 子集 => observe 输出唯一标签。
  const MARKERS = MARKER_PRIORITY
  let ok = priorityOk
  let count = 0
  for (let mask = 0; mask < (1 << MARKERS.length); mask++) {
    const markers = {}
    MARKERS.forEach((mm, i) => {
      markers[mm] = (mask >> i) & 1
    })
    count++
    const label = observe(markers)
    const expected = MARKERS.find((mm) => markers[mm]) ?? 'none'
    if (label !== expected) ok = false
    if (!MARKERS.includes(label) && label !== 'none') ok = false
  }
  const subsetCountOk = count === m.expectedSubsets
  if (!subsetCountOk) ok = false
  evidence.push(
    `2^${MARKERS.length}=${count} 子集（含空集）：observe 全部唯一且等于最高优先级标记 = ` +
      `${ok && subsetCountOk ? 'PASS' : 'FAIL'}` +
      (subsetCountOk ? '' : `（实跑 ${count} ≠ spec 预期 ${m.expectedSubsets}）`)
  )

  // 五态各自唯一标签（单标记映射），evidence 文本按实际结果输出（不再无条件 PASS）。
  let singleOk = true
  for (const mm of MARKERS) {
    const markers = { done: 0, running: 0, stopping: 0, adopted: 0, orphaned: 0 }
    markers[mm] = 1
    if (observe(markers) !== mm) singleOk = false
  }
  if (!singleOk) ok = false
  evidence.push(`五态单标记映射：${MARKERS.join('/')} 各自映射到自身 = ${singleOk ? 'PASS' : 'FAIL'}`)

  // 共存组合仍唯一（证伪"恰一主标记"虚假不变量：多标记可共存）。
  const coex = m.coexist.markers
  const coexLabel = observe(coex)
  const coexOk = coexLabel === m.coexist.expectedLabel
  if (!coexOk) ok = false
  evidence.push(
    `共存组合 ${JSON.stringify(coex)} => 唯一标签 "${coexLabel}"（spec 预期 "${m.coexist.expectedLabel}"） = ${coexOk ? 'PASS' : 'FAIL'}`
  )

  return {
    ...baseResult(spec),
    status: ok ? 'pass' : 'fail',
    summary: ok
      ? `observe 优先级（${MARKER_PRIORITY.join('>')}）对全部 ${m.expectedSubsets} 个标记子集（含空集）输出唯一且确定的标签；多标记共存时仍唯一（修正"恰一主标记"虚假不变量）。`
      : 'observe 标签不唯一、优先级与 spec 声明不符，或子集例数与 spec 预期不符。',
    evidence,
    counterexample: null,
    details: { priority: MARKER_PRIORITY, coex: { markers: coex, label: coexLabel } },
  }
}

// ---------------------------------------------------------------------------
// 运行器与 CLI
// ---------------------------------------------------------------------------

const CHECKERS = {
  'E-1': checkE1,
  'E-2': checkE2,
  'E-3': checkE3,
  'E-4': checkE4,
  'E-5': checkE5,
  'E-6': checkE6,
}

function runAll(specsArg) {
  const byId = specsArg && specsArg.byId ? specsArg.byId : loadSpecs().byId
  return SPEC_IDS.map((id) => CHECKERS[id](byId[id]))
}

function humanSummary(results) {
  const lines = []
  lines.push('=== ASM-FS 有界模型检查器（BMC，spec 驱动）结果 ===')
  lines.push('')
  for (const r of results) {
    lines.push(`[${r.status === 'pass' ? 'PASS' : 'FAIL'}] ${r.id} ${r.title}`)
    lines.push(`  边界: ${r.boundary}`)
    if (r.status === 'fail' && r.counterexample) {
      lines.push(`  反例: ${r.counterexample.reason}`)
    }
    for (const e of r.evidence) lines.push(`  · ${e}`)
    lines.push('')
  }
  const pass = results.filter((r) => r.status === 'pass').length
  lines.push(`合计: ${pass}/${results.length} 条通过`)
  return lines.join('\n')
}

function parseArgv(argv) {
  const out = { wantJson: false, specsDir: null, ids: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--json') out.wantJson = true
    else if (a === '--specs-dir') {
      out.specsDir = argv[i + 1]
      i++
    } else if (a.startsWith('--')) {
      // 忽略未知 flag。
    } else {
      out.ids.push(a)
    }
  }
  return out
}

function main() {
  const { wantJson, specsDir, ids } = parseArgv(process.argv.slice(2))

  let loaded
  try {
    loaded = loadSpecs(specsDir ? resolve(process.cwd(), specsDir) : SPECS_DIR)
  } catch (e) {
    console.error(e.message)
    console.error('spec 加载失败：检查器以 specs/E-1~E-6.json 为唯一参数来源，缺失/损坏即中止，拒绝硬编码自证。')
    process.exit(2)
  }

  let results
  if (ids.length === 0) {
    results = runAll(loaded)
  } else {
    const unknown = ids.filter((i) => !loaded.byId[i])
    if (unknown.length > 0) {
      console.error(`未知定理: ${unknown.join(', ')}；可用: ${Object.keys(loaded.byId).join(', ')}`)
      process.exit(2)
    }
    results = ids.map((id) => CHECKERS[id](loaded.byId[id]))
  }

  const payload = {
    engine: 'ASM-FS bounded model checker (BMC) — spec-driven',
    zeroDeps: true,
    specDriven: true,
    specs: SPEC_IDS.map((id) => ({ id, sha256: loaded.hashes[id] })),
    note: '有界穷举 ≠ 全称证明；O_EXCL 与 rename 原子性为公理（OS 保证，代码外假设）。每个定理的参数/断言/预期状态空间均来自 specs/E-*.json 的 model 字段。',
    runAt: new Date().toISOString(),
    theorems: results,
    summary: {
      total: results.length,
      pass: results.filter((r) => r.status === 'pass').length,
      fail: results.filter((r) => r.status === 'fail').length,
    },
  }

  if (wantJson) {
    console.log(JSON.stringify(payload, null, 2))
  } else {
    console.log(humanSummary(results))
    console.log('--- 结构化 JSON ---')
    console.log(JSON.stringify(payload, null, 2))
  }

  const allPass = payload.summary.fail === 0
  process.exit(allPass ? 0 : 1)
}

// 作为模块被 import 时不执行 CLI（便于测试/复用）。
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main()
}

export {
  liveness,
  observe,
  step,
  search,
  replay,
  MARKER_PRIORITY,
  loadSpecs,
  SPEC_IDS,
  checkE1,
  checkE2,
  checkE3,
  checkE4,
  checkE5,
  checkE6,
  runAll,
}
