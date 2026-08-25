// phase7/nat-classify.mjs —— NAT 类型自分类（零依赖，node:dgram）
//
// 把本报告 R2-R4 的实测结论固化为「节点自分类」原语，供打洞状态机（punch-plan.mjs）
// 做第一分支决策。分类只依赖 2~3 个可达 STUN 服务器 + 一个可配合的过滤探针服务器，
// 全部 node:* 内置模块。
//
// 分类维度与实测依据（见 vap-punch-routes.md）：
//   映射类 mappingClass —— 决定「对称 vs 锥」，是打洞可行性的第一分支：
//     'endpoint-independent'  cone（锥）：同 socket 对不同目的 → 映射端口恒等
//         → A 实测（R2 E1 两目的端口恒等 20834/20836）。可打洞（回打实际源）。
//     'address-dependent'     同 socket 对不同目的 IP → 映射随 IP 变；同 IP 异端口仍恒等
//         → R1 曾误判为对称，R2 纠正为测量误差（两 socket）。
//     'symmetric'             address-and-port-dependent：同 socket 对同 IP 异端口 → 映射也变
//         → R3 E8 忠实模拟器实测（52009 vs 52114），UDP 打洞判死（E10/E11）。
//   过滤类 filter —— 仅对 cone 有意义，决定「谁能反向发起」：
//     'full-cone'          任意源可入 → 对端任意侧可发起
//     'restricted-cone'    仅本端发过的那台主机(IP)可入
//     'port-restricted'    仅本端发过的那台主机(IP:port)可入 → 对端必须回打实际源
//         → A 实测（R3 E9 陌生源端口 0 回复）判定为 port-restricted-cone。
//   公网判定 isPublic —— 映射 IP==本地 IP 且端口保持 → 无 NAT（或 1:1 全锥公网）
//         → B 宿主实测（R2 E6：46501→46501 端口保持）。
//
// 判定流程（RFC 5780 行为测试简化，同一 socket 串行发 Binding Request）：
//   1) 同 socket 向 S1(ip1:p1) 与 S2(ip2:p2) 各发一次，比较 XOR-MAPPED-ADDRESS。
//   2) M1.port == M2.port  → endpoint-independent（cone）
//   3) M1.port != M2.port  → 再向 S1 的第二端口 S1b(ip1:p1') 发：
//        M1.port == M1b.port → address-dependent
//        M1.port != M1b.port → symmetric
//   4) 过滤测试（可选，需配合服务器）：保持 socket，服务器从「A 未联系过的源端口」回发：
//        收到 → 非端口受限（full-cone / restricted-cone）
//        超时 → port-restricted-cone

import dgram from 'node:dgram';
import crypto from 'node:crypto';

const MAGIC = Buffer.from([0x21, 0x12, 0xa4, 0x42]);

// 解析 XOR-MAPPED-ADDRESS（attrs 从 offset 0 起，遍历 TLV）
function parseXorMappedAddress(attrs) {
  let off = 0;
  while (off + 4 <= attrs.length) {
    const type = attrs.readUInt16BE(off);
    const len = attrs.readUInt16BE(off + 2);
    if (off + 4 + len > attrs.length) break;
    if (type === 0x0020 && len >= 8) {
      const family = attrs.readUInt16BE(off + 4);
      const xorPort = attrs.readUInt16BE(off + 6);
      const port = xorPort ^ MAGIC.readUInt16BE(0);
      if (family === 0x01) {
        const ip = [0, 1, 2, 3].map((i) => attrs[off + 8 + i] ^ MAGIC[i]).join('.');
        return { ip, port };
      }
    }
    off += 4 + len + ((4 - (len % 4)) % 4);
  }
  return null;
}

// 向 host:port 发一次 STUN Binding Request，返回 XOR-MAPPED-ADDRESS（{ip, port}）
function stunBinding(socket, host, port, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const txId = crypto.randomBytes(12);
    const req = Buffer.alloc(20);
    req.writeUInt16BE(0x0001, 0);
    req.writeUInt16BE(0, 2);
    MAGIC.copy(req, 4);
    txId.copy(req, 8);
    const timeout = setTimeout(() => { socket.off('message', handler); reject(new Error(`STUN timeout ${host}:${port}`)); }, timeoutMs);
    const handler = (msg) => {
      if (msg.length < 20 || msg.readUInt16BE(0) !== 0x0101) return;
      if (!msg.subarray(8, 20).equals(txId)) return;
      clearTimeout(timeout);
      socket.off('message', handler);
      const m = parseXorMappedAddress(msg.subarray(20));
      if (m) resolve(m); else reject(new Error('no XOR-MAPPED-ADDRESS'));
    };
    socket.on('message', handler);
    socket.send(req, port, host);
  });
}

// 主分类入口。
//   servers: [{ host, port }] 至少 2 个不同 IP；若给第 3 个「与 servers[0] 同 IP 异端口」，
//            则能区分 address-dependent vs symmetric。
//   localPort: 本地绑定端口（0=随机）。
// 返回 { mappingClass, filter, isPublic, evidence }。
//   filter 仅在 mappingClass==='endpoint-independent' 时有意义，默认 'unknown'。
export async function classifyNAT({ servers, localPort = 0 } = {}) {
  if (!Array.isArray(servers) || servers.length < 2) {
    throw new Error('classifyNAT 需要至少 2 个不同 IP 的 STUN 服务器');
  }
  const socket = dgram.createSocket('udp4');
  await new Promise((resolve, reject) => {
    socket.once('error', reject);
    socket.bind(localPort, '0.0.0.0', resolve);
  });
  const local = socket.address();
  const evidence = { local: `${local.address}:${local.port}`, samples: [] };

  try {
    const m1 = await stunBinding(socket, servers[0].host, servers[0].port);
    evidence.samples.push({ server: servers[0], mapping: m1 });
    const m2 = await stunBinding(socket, servers[1].host, servers[1].port);
    evidence.samples.push({ server: servers[1], mapping: m2 });

    const sameIpDiffPort = servers[0].host === servers[1].host && servers[0].port !== servers[1].port;
    let mappingClass;
    if (m1.port === m2.port) {
      mappingClass = 'endpoint-independent';
    } else if (sameIpDiffPort) {
      // 同 IP 不同端口 → 映射端口不同 = endpoint-and-port-dependent，确定 symmetric（R3 E8 判据）
      mappingClass = 'symmetric';
      evidence.note = `同 IP 异端口（${servers[0].host}:${servers[0].port} vs ${servers[1].port}）映射端口不同 → 确定 symmetric`;
    } else if (servers.length >= 3) {
      const m1b = await stunBinding(socket, servers[2].host, servers[2].port);
      evidence.samples.push({ server: servers[2], mapping: m1b });
      mappingClass = (m1.port === m1b.port) ? 'address-dependent' : 'symmetric';
    } else {
      // 无法区分 address-dependent vs symmetric：保守判为 symmetric（更坏情形）
      mappingClass = 'symmetric';
      evidence.note = '仅 2 个异 IP 服务器，M1!=M2 保守判 symmetric；补第 3 个同 IP 异端口服务器可精化';
    }

    // 公网判定：映射 IP == 本地 IP 且端口保持 → 无 NAT（或 1:1 全锥公网）
    const isPublic = (m1.ip === local.address) && (m1.port === local.port);

    return { mappingClass, filter: 'unknown', isPublic, evidence };
  } finally {
    try { socket.close(); } catch {}
  }
}

// 过滤测试（可选，仅对 cone 有意义，需配合服务器）：
//   调用方保持一个已 STUN 学得映射的 socket，服务器从「本端未联系过的源端口」向映射发 UDP。
//   收到 → 返回 'not-port-restricted'（full-cone 或 restricted-cone，可再交叉 IP 精化）
//   超时 → 返回 'port-restricted-cone'
// 服务器侧复用 vap-local/r3/filter-probe.mjs（--target ip:port --srcPort 未联系端口）。
export function probeFiltering({ socket, mapping, timeoutMs = 6000 }) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { socket.off('message', handler); resolve('port-restricted-cone'); }, timeoutMs);
    const handler = (msg, rinfo) => {
      // 任何来自「陌生源」的包都视为过滤探针命中（实际部署应按内容/token 判定）
      clearTimeout(timer);
      socket.off('message', handler);
      resolve('not-port-restricted');
    };
    socket.on('message', handler);
    // 触发方需先通知服务器发探针；此处只负责监听。
    socket.emit('_filterProbeArmed', { mapping });
  });
}

export const __test = { parseXorMappedAddress, stunBinding };
