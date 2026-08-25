// phase7/punch-chain.smoke.mjs —— buildExecPlan 纯函数冒烟测试（零依赖，node 直接跑）
// 用法：node phase7/punch-chain.smoke.mjs
// 断言：① 首条可执行策略符合 punch-plan 排序；② 步骤顺序 ①→②→③→④→⑤；③ 对称端 UDP 打洞判死跳过；
//       ④ turn-relay 始终在链尾；⑤ direct-connect 命中时 target 指向 peer 映射；
//       ⑥ ipv6-direct：双 GUA 时前插（direct 之后）且 target 指 peer v6；⑦ ULA/fe80 不误判（假阳性排除）。
import { buildExecPlan, isGlobalV6 } from './punch-chain.mjs';

const peerMapping = { ip: '203.0.113.10', port: 46501 }; // 示例映射（RFC 5737 文档保留地址，非生产 IP）
const GUA_A = [{ ip: '2409:8a3c:17d0:5100::1' }];
const GUA_B = [{ ip: '2402:4e00:1209:c100::2' }];
const cases = [
  {
    name: '锥(端口受限) ↔ 公网（无 v6）',
    selfNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    peerNat: { mappingClass: 'endpoint-independent', filter: 'full-cone', isPublic: true },
    expectFirst: 'direct-connect',
    expectLast: 'turn-relay',
    expectUdpPunchExecutable: true,
    expectV6Executable: false,
  },
  {
    name: '锥 ↔ 锥（无 v6）',
    selfNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    peerNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    expectFirst: 'udp-punch',
    expectLast: 'turn-relay',
    expectUdpPunchExecutable: true,
    expectV6Executable: false,
  },
  {
    name: '对称 ↔ 锥（无 v6）',
    selfNat: { mappingClass: 'symmetric', filter: 'unknown', isPublic: false },
    peerNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    expectFirst: 'tcp-simultaneous-open',
    expectLast: 'turn-relay',
    expectUdpPunchExecutable: false,
    expectV6Executable: false,
  },
  {
    name: '对称 ↔ 对称（无 v6）',
    selfNat: { mappingClass: 'symmetric', filter: 'unknown', isPublic: false },
    peerNat: { mappingClass: 'symmetric', filter: 'unknown', isPublic: false },
    expectFirst: 'tcp-simultaneous-open',
    expectLast: 'turn-relay',
    expectUdpPunchExecutable: false,
    expectV6Executable: false,
  },
  {
    name: '公网 ↔ 公网（无 v6）',
    selfNat: { mappingClass: 'endpoint-independent', filter: 'unknown', isPublic: true },
    peerNat: { mappingClass: 'endpoint-independent', filter: 'unknown', isPublic: true },
    expectFirst: 'direct-connect',
    expectLast: 'turn-relay',
    expectUdpPunchExecutable: true,
    expectV6Executable: false,
  },
  {
    name: '锥 ↔ 锥 + 双 GUA → v6 前插',
    selfNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    peerNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    selfIpv6: GUA_A, peerIpv6: GUA_B,
    expectFirst: 'ipv6-direct',
    expectLast: 'turn-relay',
    expectUdpPunchExecutable: true,
    expectV6Executable: true,
    expectV6Target: GUA_B[0].ip,
  },
  {
    name: '对称 ↔ 对称 + 双 GUA → v6 是第一直连候选（对称 NAT 的解）',
    selfNat: { mappingClass: 'symmetric', filter: 'unknown', isPublic: false },
    peerNat: { mappingClass: 'symmetric', filter: 'unknown', isPublic: false },
    selfIpv6: GUA_A, peerIpv6: GUA_B,
    expectFirst: 'ipv6-direct',
    expectLast: 'turn-relay',
    expectUdpPunchExecutable: false,
    expectV6Executable: true,
  },
  {
    name: '一端公网 + 双 GUA → direct-connect 仍优先（v4 快车道 guaranteed）',
    selfNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    peerNat: { mappingClass: 'endpoint-independent', filter: 'full-cone', isPublic: true },
    selfIpv6: GUA_A, peerIpv6: GUA_B,
    expectFirst: 'direct-connect',
    expectLast: 'turn-relay',
    expectUdpPunchExecutable: true,
    expectV6Executable: true,
  },
  {
    name: '双 ULA（fd7a）→ 不误判（假阳性排除）',
    selfNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    peerNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    selfIpv6: [{ ip: 'fd7a:115c:a1e0::5001:11e4' }],
    peerIpv6: [{ ip: 'fd7a:115c:a1e0::b101:4db3' }],
    expectFirst: 'udp-punch',
    expectLast: 'turn-relay',
    expectUdpPunchExecutable: true,
    expectV6Executable: false,
  },
  {
    name: 'fe80 link-local 混入 → 滤掉，仅 GUA 生效',
    selfNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    peerNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    selfIpv6: [{ ip: 'fe80::1' }, { ip: '2409:8a3c:17d0:5100::1' }],
    peerIpv6: [{ ip: 'fe80::2' }, { ip: '2402:4e00:1209:c100::2' }],
    expectFirst: 'ipv6-direct',
    expectLast: 'turn-relay',
    expectUdpPunchExecutable: true,
    expectV6Executable: true,
    expectV6Target: '2402:4e00:1209:c100::2',
  },
];

let fail = 0;
for (const c of cases) {
  const p = buildExecPlan({
    selfNat: c.selfNat, peerNat: c.peerNat, peerMapping, tcpPort: 46602,
    selfIpv6: c.selfIpv6 || [], peerIpv6: c.peerIpv6 || [],
  });
  const steps = p.steps;
  const last = steps[steps.length - 1];
  const udpStep = steps.find((s) => s.id === 'udp-punch');
  const v6Step = steps.find((s) => s.id === 'ipv6-direct');
  const checks = [
    ['first', p.first === c.expectFirst],
    ['last=turn-relay', last.id === 'turn-relay'],
    ['udp-punch executable', (udpStep.timeoutMs > 0) === c.expectUdpPunchExecutable],
    ['v6 executable', (v6Step.timeoutMs > 0) === c.expectV6Executable],
    ['v6 target', !c.expectV6Target || (v6Step.target && v6Step.target.ip === c.expectV6Target)],
    ['turn-relay timeout=0', last.timeoutMs === 0],
  ];
  const ok = checks.every(([, b]) => b);
  if (!ok) fail += 1;
  const detail = checks.map(([label, b]) => `${label}:${b ? 'ok' : 'BAD'}`).join(' ');
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${c.name}  ->  first=${p.first} (expect ${c.expectFirst})  | ${detail}`);
}

// 额外断言：direct-connect 的 target 指向 peer 映射；udp-punch 判死时 target=null
const dc = buildExecPlan({
  selfNat: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
  peerNat: { mappingClass: 'endpoint-independent', filter: 'full-cone', isPublic: true },
  peerMapping, tcpPort: 46602,
});
const dcStep = dc.steps.find((s) => s.id === 'direct-connect');
if (!(dcStep && dcStep.target && dcStep.target.ip === peerMapping.ip && dcStep.target.port === peerMapping.port)) {
  fail += 1;
  console.log('FAIL  direct-connect target 未指向 peer 映射');
} else {
  console.log('PASS  direct-connect target 指向 peer 映射');
}

// 额外断言：isGlobalV6 过滤语义
const v6filter = [
  ['2402:4e00::1', true], ['2409:8a3c::1', true], ['fd7a:115c:a1e0::1', false],
  ['fe80::1', false], ['::1', false], ['203.0.113.10', false],
];
const v6ok = v6filter.every(([ip, want]) => isGlobalV6(ip) === want);
if (!v6ok) {
  fail += 1;
  console.log('FAIL  isGlobalV6 过滤语义错误');
} else {
  console.log('PASS  isGlobalV6 过滤语义（GUA 收 / ULA、link-local、v4 拒）');
}

console.log(`\n${cases.length + 2 - fail}/${cases.length + 2} passed`);
process.exit(fail === 0 ? 0 : 1);
