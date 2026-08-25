// phase7/punch-chain.mjs —— 把 punch-plan 的策略链映射为 punch-node 可执行的步骤表（纯函数，零依赖）
//
// 职责：只做「分类结果 → 有序可执行步骤」的纯映射，不触碰 socket / 网络。punch-node 拿到
// 步骤表后按序执行、失败按链回落（① direct-connect ② udp-punch ③ tcp-so ④ turn-relay）。
// 这样「选哪条策略、每条给什么目标/超时/依据」是可单测的，执行副作用留在 punch-node。
//
// 输入：
//   selfNat / peerNat : nat-classify.mjs 的 classifyNAT() 输出 { mappingClass, filter, isPublic }
//   selfMapping / peerMapping : STUN/中继学到的公网映射 { ip, port }
//   selfIpv6 / peerIpv6 : 全局单播 IPv6 列表 [{ ip }]（punch-node 已排除 fe80/fc/fd）
//   tcpPort : TCP simultaneous open 使用的端口（两端约定一致；缺省用 localPort+2）
//
// 输出：
//   { summary, first, steps: [{ id, timeoutMs, target:{ip,port}|null, note, basis }] }
//   timeoutMs <= 0 表示「不执行」：udp-punch 遇对称端判死跳过、tcp-so 一端公网不适用、ipv6-direct 无 GUA 跳过、turn-relay 兜底始终在列。

import { selectStrategy } from './punch-plan.mjs';

// 全局单播 v6 判定（防御性再过滤：punch-node 的 globalIpv6 已过滤，这里兜底防 ULA/link-local/loopback 误判）
export function isGlobalV6(ip) {
  const a = String(ip || '').toLowerCase();
  return a.includes(':') && a !== '::1'
    && !a.startsWith('fe80') && !a.startsWith('fc') && !a.startsWith('fd');
}
const normV6 = (list) => (Array.isArray(list) ? list : [])
  .map((x) => (typeof x === 'string' ? x : x && x.ip))
  .filter((x) => typeof x === 'string' && isGlobalV6(x));

export function buildExecPlan({ selfNat, peerNat, selfMapping, peerMapping, selfIpv6 = [], peerIpv6 = [], tcpPort = 0 } = {}) {
  const selfG = normV6(selfIpv6);
  const peerG = normV6(peerIpv6);
  const s = selectStrategy(selfNat, peerNat, { selfIpv6: selfG, peerIpv6: peerG });
  const udpTarget = peerMapping && peerMapping.ip ? { ip: peerMapping.ip, port: peerMapping.port } : null;
  // v6 端口优先取 peer 显式宣告的 v6Port（= 对端 v6 socket 端口）；缺省回退映射端口+10 的约定偏移。
  // 不能用映射端口+10 硬推：家庭 NAT 映射端口随机（如 localPort 46000 映射成 20701），偏移会打错端口。
  const peerV6Port = (peerMapping && peerMapping.v6Port) ? peerMapping.v6Port
    : (udpTarget ? udpTarget.port + 10 : 0);
  const v6Target = (peerG.length > 0 && udpTarget)
    ? { ip: peerG[0], port: peerV6Port } : null;
  const steps = [];

  for (const c of s.chain) {
    if (c.id === 'direct-connect') {
      steps.push({
        id: c.id, timeoutMs: c.timeoutMs, target: udpTarget, note: c.action, basis: c.basis,
      });
    } else if (c.id === 'ipv6-direct') {
      // timeoutMs>0 = 两端均有 GUA 可执行；<=0 = 任一端无 GUA 跳过
      steps.push({
        id: c.id, timeoutMs: c.timeoutMs,
        target: c.timeoutMs > 0 ? v6Target : null,
        note: c.action, basis: c.basis,
      });
    } else if (c.id === 'udp-punch') {
      // timeoutMs>0 = 可执行（锥↔锥）；<=0 = 判死跳过（任一端 symmetric）
      steps.push({
        id: c.id, timeoutMs: c.timeoutMs,
        target: c.timeoutMs > 0 ? udpTarget : null,
        note: c.action, basis: c.basis,
      });
    } else if (c.id === 'tcp-simultaneous-open') {
      // timeoutMs>0 = best-effort 可执行（两端都在 NAT 后）；<=0 = 一端公网不适用
      steps.push({
        id: c.id, timeoutMs: c.timeoutMs,
        target: (c.timeoutMs > 0 && peerMapping && peerMapping.ip) ? { ip: peerMapping.ip, port: tcpPort } : null,
        note: c.action, basis: c.basis,
      });
    } else if (c.id === 'turn-relay') {
      // 兜底始终在列（timeoutMs=0 表示「不轮询等待，连接即可用」）
      steps.push({
        id: c.id, timeoutMs: 0, target: null, note: c.action, basis: c.basis,
      });
    } else {
      steps.push({ id: c.id, timeoutMs: c.timeoutMs || 0, target: null, note: c.action, basis: c.basis });
    }
  }

  // 首条「可执行」策略（timeoutMs>0 者），否则 turn-relay 兜底
  const firstExecutable = steps.find((st) => st.timeoutMs > 0);
  return {
    summary: s.summary,
    first: firstExecutable ? firstExecutable.id : 'turn-relay',
    steps,
  };
}
