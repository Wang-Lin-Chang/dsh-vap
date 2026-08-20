// experiments/phase0-experiment.mjs —— VAP Phase 0 实测装置（P0-1 .. P0-4）
//
// 运行：node phase0/experiments/phase0-experiment.mjs
// 输出：结构化 JSON（stdout + phase0/experiments/phase0-results.json）
//
// 四组实验（依据 phase0/DESIGN.md §三）：
//   P0-1 裸身份基线：1000 个裸密钥对耗时 → 单身份 ms（预期 <1ms）
//   P0-2 伪造拦截：三种伪造各 100 个 → 验证门拒绝率（必须 100%）
//   P0-3 诚实成本曲线：difficulty 1000/10000/100000 各完成 1 凭证 → 成本 ms
//   P0-4 杠杆结论：C_bare / C_honest 比值 + 伪造拦截率 + 假设判定
//
// 零第三方依赖：仅 node:crypto / node:fs / node:path 与相对路径 import。

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  makeTask,
  solveTask,
  verifySolution,
  createAuditors,
  auditorPublicKeys,
  forgeCredential,
  verifyCredential,
  verifyCredentialDetailed,
  forgeFake,
} from '../history-forge.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function nowMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function run(label, fn) {
  const t0 = nowMs();
  const value = fn();
  const ms = nowMs() - t0;
  return { ms, value };
}

// ---------------------------------------------------------------------------
// P0-1 裸身份基线：1000 个裸密钥对耗时
// ---------------------------------------------------------------------------
const p01 = (() => {
  const N = 1000;
  const { ms } = run('P0-1', () => {
    for (let i = 0; i < N; i++) crypto.generateKeyPairSync('ed25519');
  });
  const bareMs = ms / N;
  return { label: 'bare identity baseline', keypairs: N, totalMs: ms, bareMs };
})();

// ---------------------------------------------------------------------------
// P0-2 伪造拦截：三种伪造各 100 个，验证门拒绝率必须 100%
// ---------------------------------------------------------------------------
const p02 = (() => {
  const PER_KIND = 100;
  const kinds = ['randomSolution', 'fakeSig', 'duplicateAuditor'];
  const perKind = {};
  let attempted = 0;
  let rejected = 0;
  const sampleReasons = {};

  for (const kind of kinds) {
    let kindRejected = 0;
    let kindAttempted = 0;
    for (let i = 0; i < PER_KIND; i++) {
      const { credential, auditorKeys } = forgeFake({ kind });
      const result = verifyCredentialDetailed(credential, auditorKeys);
      kindAttempted += 1;
      if (!result.pass) {
        kindRejected += 1;
        if (!sampleReasons[kind]) sampleReasons[kind] = result.reasons;
      }
    }
    attempted += kindAttempted;
    rejected += kindRejected;
    perKind[kind] = {
      attempted: kindAttempted,
      rejected: kindRejected,
      rejectRate: kindAttempted === 0 ? null : kindRejected / kindAttempted,
      sampleReasons: sampleReasons[kind] || [],
    };
  }

  const rejectRate = attempted === 0 ? null : rejected / attempted;
  return {
    label: 'forgery interception',
    perKindCount: PER_KIND,
    perKind,
    overall: { attempted, rejected, rejectRate },
  };
})();

// ---------------------------------------------------------------------------
// P0-3 诚实成本曲线：difficulty 1000/10000/100000 各完成 1 凭证
// ---------------------------------------------------------------------------
const p03 = (() => {
  const difficulties = [1000, 10000, 100000];
  const seed = 'phase0-honest-seed';
  const costs = [];
  for (const difficulty of difficulties) {
    const task = makeTask(seed, difficulty);
    const solveRun = run('solve', () => solveTask(task));
    let cred = null;
    let keys = {};
    const credRun = run('forge', () => {
      const auditors = createAuditors(3);
      keys = auditorPublicKeys(auditors);
      cred = forgeCredential({ task, solution: solveRun.value, auditors });
      return cred;
    });
    costs.push({
      difficulty,
      solveMs: solveRun.ms,
      credentialMs: credRun.ms,
      verified: verifyCredential(cred, keys),
      solution: cred.solution.slice(0, 16) + '…',
      auditors: cred.auditors.length,
    });
  }
  return { label: 'honest cost curve', seed, costs };
})();

// ---------------------------------------------------------------------------
// P0-4 杠杆结论 + 确定性 / 绑定性自检
// ---------------------------------------------------------------------------
const p04 = (() => {
  // 确定性：同 seed 独立两次求解必须同解
  const task = makeTask('determinism-check', 100);
  const s1 = solveTask(task);
  const s2 = solveTask(task);
  const deterministic = s1 === s2;

  // 绑定性自检：真实凭证通过；篡改 work/solution/sig 任一必失败
  const auditors = createAuditors(3);
  const keys = auditorPublicKeys(auditors);
  const realTask = makeTask('binding-check', 100);
  const realSolution = solveTask(realTask);
  const real = forgeCredential({ task: realTask, solution: realSolution, auditors });

  const validPasses = verifyCredential(real, keys);
  const tamperSeed = verifyCredential({ ...real, work: { ...real.work, seed: 'tampered-seed' } }, keys);
  const tamperDifficulty = verifyCredential(
    { ...real, work: { ...real.work, difficulty: real.work.difficulty + 1 } },
    keys,
  );
  const tamperSolution = verifyCredential({ ...real, solution: crypto.randomBytes(32).toString('hex') }, keys);
  const tamperSig = verifyCredential(
    { ...real, auditors: [{ ...real.auditors[0], sig: crypto.randomBytes(64).toString('base64') }, ...real.auditors.slice(1)] },
    keys,
  );

  // 杠杆：C_honest 取 difficulty=1000 的凭证耗时（与 C_bare 同量级对比最直观）
  const honestMs = p03.costs[0].credentialMs;
  const bareMs = p01.bareMs;
  const ratio = honestMs / bareMs;
  const forgeRejectRate = p02.overall.rejectRate;
  const leverageHolds = forgeRejectRate === 1.0 && ratio > 1;

  const costModel = {
    C_bare: { unit: 'ms', value: bareMs, meaning: '生成 1 个裸身份（Ed25519 密钥对）的耗时：零成本基线' },
    C_forge: {
      unit: 'ratio',
      value: forgeRejectRate,
      meaning: '伪造 1 个有历史凭证：跳过工作编造 solution / 伪造审计签名 / 审计者重复，全部被重放验证 100% 拦截，唯一出路是真干活',
    },
    C_honest: {
      unit: 'ms',
      value: honestMs,
      meaning: '真实完成 1 个凭证（difficulty=1000 的哈希链 + 3 路独立审计重算与签名）的耗时，可由 difficulty 参数调节',
    },
    conclusion: [
      `C_bare=${bareMs.toFixed(4)}ms：伪造 1000 个裸公钥零成本，单身份毫秒级。`,
      `C_forge=${(forgeRejectRate * 100).toFixed(0)}% 拦截：三种伪造路径（编造 solution / 伪造签名 / 审计者重复）合计 ${p02.overall.attempted} 个伪造件全部被验证门拒绝，伪造者无法跳过工作量。`,
      `C_honest=${honestMs.toFixed(3)}ms@difficulty1000：诚实成本可调（difficulty 1000/10000/100000 递增），稀缺性 = 可调工作成本 + 不可伪造的多路审计链。`,
      `杠杆比 C_honest/C_bare=${ratio.toFixed(1)}：伪造 1 个"有可验证历史"的身份必须付出真实工作量，历史成本杠杆成立。`,
    ].join(' '),
  };

  return {
    label: 'leverage conclusion',
    deterministic,
    determinismNote: deterministic ? 'same seed yields identical solution across independent solves' : 'DETERMINISM VIOLATED',
    binding: {
      validPasses,
      tamperSeedRejected: !tamperSeed,
      tamperDifficultyRejected: !tamperDifficulty,
      tamperSolutionRejected: !tamperSolution,
      tamperSigRejected: !tamperSig,
    },
    bareMs,
    honestMs,
    forgeRejectRate,
    ratio,
    leverageHolds,
    costModel,
  };
})();

// ---------------------------------------------------------------------------
// 汇总输出
// ---------------------------------------------------------------------------
const summary = {
  experiment: 'phase0-history-scarcity',
  generatedAt: new Date().toISOString(),
  zeroDependency: true,
  deterministic: p04.deterministic,
  P0_1: p01,
  P0_2: p02,
  P0_3: p03,
  P0_4: p04,
};

const json = JSON.stringify(summary, null, 2);
process.stdout.write(json + '\n');

const outPath = path.join(__dirname, 'phase0-results.json');
fs.writeFileSync(outPath, json + '\n', 'utf8');

// 硬性验收自检：P0-2 拒绝率必须 100%，否则以非零退出码标记失败（不伪造实验结果）。
const ok = p02.overall.rejectRate === 1.0 && p04.deterministic && p04.binding.validPasses
  && p04.binding.tamperSeedRejected && p04.binding.tamperDifficultyRejected
  && p04.binding.tamperSolutionRejected && p04.binding.tamperSigRejected;

if (!ok) {
  process.stderr.write('PHASE0 EXPERIMENT FAILED: acceptance criteria not met.\n');
  process.exitCode = 1;
} else {
  process.stderr.write(`PHASE0 OK: forgeRejectRate=${p02.overall.rejectRate} deterministic=${p04.deterministic}\n`);
}
