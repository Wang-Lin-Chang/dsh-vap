// phase7/punch-plan.smoke.mjs —— 策略选择器纯函数冒烟测试（零依赖，node 直接跑）
// 用法：node phase7/punch-plan.smoke.mjs
// 断言 selectStrategy 对 5 组分类输入输出「符合 R4 §9.4.3 最终排序」的策略链。
import { selectStrategy } from './punch-plan.mjs';

const cases = [
  {
    name: '锥(端口受限) ↔ 公网',
    self: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    peer: { mappingClass: 'endpoint-independent', filter: 'full-cone', isPublic: true },
    expectFirst: 'direct-connect',
  },
  {
    name: '锥 ↔ 锥',
    self: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    peer: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    expectFirst: 'udp-punch',
  },
  {
    name: '对称 ↔ 锥',
    self: { mappingClass: 'symmetric', filter: 'unknown', isPublic: false },
    peer: { mappingClass: 'endpoint-independent', filter: 'port-restricted', isPublic: false },
    expectFirst: 'tcp-simultaneous-open', // UDP 判死（timeout 0），首条可执行策略=TCP SO
  },
  {
    name: '对称 ↔ 对称',
    self: { mappingClass: 'symmetric', filter: 'unknown', isPublic: false },
    peer: { mappingClass: 'symmetric', filter: 'unknown', isPublic: false },
    expectFirst: 'tcp-simultaneous-open',
  },
  {
    name: '公网 ↔ 公网',
    self: { mappingClass: 'endpoint-independent', filter: 'unknown', isPublic: true },
    peer: { mappingClass: 'endpoint-independent', filter: 'unknown', isPublic: true },
    expectFirst: 'direct-connect',
  },
];

let fail = 0;
for (const c of cases) {
  const r = selectStrategy(c.self, c.peer);
  const ok = r.first === c.expectFirst;
  if (!ok) fail += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${c.name}  ->  first=${r.first} (expect ${c.expectFirst})  | ${r.summary}`);
}
console.log(`\n${cases.length - fail}/${cases.length} passed`);
process.exit(fail === 0 ? 0 : 1);
