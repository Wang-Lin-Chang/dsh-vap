// phase7/punch-plan.mjs —— 打洞策略选择器（零依赖，纯函数）
//
// 输入 self / peer 的 NAT 分类结果（来自 nat-classify.mjs），输出从「最快成功」到「兜底」
// 的策略链。把 R4 §9.4.3 的最终排序固化，并【移除 R3 曾建议的「TCP 同时打开作为对称环境
// 第二直连通道」定位】——TCP SO 现仅为 best-effort（R4 复测 ~40%，失败=映射跨连接关闭不持久）。
//
// 决策依据（全部来自 vap-punch-routes.md 实测，逐条标注）：
//   R2 E1/E2  : A=cone，A↔B(公网) UDP 打洞双向直连成功（directReceived=2598/437+）
//   R3 E8/E10/E11 : 真对称 NAT 双向 UDP 打洞判死（对称→端口受限锥 0 收；锥→对称预测 0 收）
//   R3 E13    : TURN 1400B 大包 120.2 KB/s ≈ 1 Mbps 上行天花板
//   R4 E16/E17/E18 : A 的 TCP 映射并发端点无关、跨关闭不持久；TCP SO 复测 ~40%
//
// 策略链顺序（从最快成功到兜底）：
//   ① direct-connect  任一端公网(isPublic) 或 全锥(full-cone) → 直接 connect 快车道
//   ② ipv6-direct     两端均有全局单播 IPv6（GUA）→ v6 UDP 互发直连（不依赖 v4 NAT 分类）
//   ③ udp-punch       两端均 endpoint-independent(cone) → 锥侧主动发起 + 回打实际源 rinfo
//   ④ tcp-so          best-effort：UDP 失败/含对称端时的次选直连，独立信令 + ≤5s 短超时
//   ⑤ turn-relay      始终在线的兜底（DCUtR 骨架）

// self / peer: { mappingClass, filter, isPublic }（filter 默认 'unknown'）
// ipv6: { selfIpv6: [{ip}], peerIpv6: [{ip}] } —— 全局单播 v6 列表（已排除 fe80/fc/fd，punch-node 侧过滤）
export function selectStrategy(self, peer, { selfIpv6 = [], peerIpv6 = [] } = {}) {
  const norm = (n) => ({
    mappingClass: n?.mappingClass || 'unknown',
    filter: n?.filter || 'unknown',
    isPublic: !!n?.isPublic,
  });
  const s = norm(self);
  const p = norm(peer);

  const bothCone = s.mappingClass === 'endpoint-independent' && p.mappingClass === 'endpoint-independent';
  const anySymmetric = s.mappingClass === 'symmetric' || p.mappingClass === 'symmetric';
  const anyPublic = s.isPublic || p.isPublic;
  const anyFullCone = s.filter === 'full-cone' || p.filter === 'full-cone';
  const bothBehindNAT = !s.isPublic && !p.isPublic;

  const chain = [];

  // ① 直接 connect 快车道（最快成功）
  if (anyPublic || anyFullCone) {
    const who = (s.isPublic || s.filter === 'full-cone') ? 'self' : 'peer';
    chain.push({
      id: 'direct-connect',
      order: 1,
      when: '任一端 isPublic（无 NAT/1:1 公网）或 filter=full-cone（接受任意源）',
      action: `${who === 'self' ? '对端' : '本端'}直接 connect 到 ${who} 的映射地址，无需打洞`,
      success: 'guaranteed（R2 实测 A↔公网 B 直连；全锥天然接受任意源）',
      timeoutMs: 3000,
      basis: '[已实测 R2 E2/E6]',
    });
  }

  // ② IPv6 直连（不依赖 v4 NAT 分类；两端均有 GUA 即可，家庭有状态防火墙由互发开洞）
  const bothV6 = Array.isArray(selfIpv6) && selfIpv6.length > 0 && Array.isArray(peerIpv6) && peerIpv6.length > 0;
  chain.push({
    id: 'ipv6-direct',
    order: 2,
    when: bothV6 ? '两端均有全局单播 IPv6（GUA，已排除 fe80/fc/fd）'
                 : '任一端无全局单播 IPv6 —— 跳过（不把 ULA/link-local 当直连地址）',
    action: bothV6 ? '双端向对方 GUA:localPort 互发 UDP 握手，回包按内容判定（from 字段），不依赖 v4 映射'
                   : '不发起 v6 直连',
    success: bothV6 ? '高（公网 v6 无 NAT；有状态防火墙由双端出站互发开洞）' : '不适用',
    timeoutMs: bothV6 ? 5000 : 0,
    basis: bothV6 ? '[装置实测 IPV6-REPORT：本机 2409↔腾讯云 2402 ICMP/UDP 均通 30ms]' : '[推理：无 GUA 即无 v6 路径]',
  });

  // ③ UDP 打洞（锥侧主动发起 + 回打实际源）
  if (bothCone) {
    chain.push({
      id: 'udp-punch',
      order: 3,
      when: 'self 与 peer 均为 endpoint-independent（cone）',
      action: '双端同时向对方映射发握手；回包必须发到 rinfo 实际源（对称映射端口会变，按内容/token 判定而非端口）',
      success: '高（R2 实测 A↔B directReceived=2598/437+）',
      timeoutMs: 15000,
      basis: '[已实测 R2 E1/E2]',
    });
  } else if (anySymmetric) {
    chain.push({
      id: 'udp-punch',
      order: 3,
      when: '任一端 symmetric —— 跳过 UDP 打洞',
      action: '不发起 UDP 打洞：E10（对称→端口受限锥 0 收）+ E11（锥→对称预测 0 收）双向判死',
      success: '不可行（判死）',
      timeoutMs: 0,
      basis: '[已实测 R3 E8/E10/E11]',
    });
  }

  // ④ TCP simultaneous open（best-effort）
  if (bothBehindNAT) {
    const sym = anySymmetric;
    chain.push({
      id: 'tcp-simultaneous-open',
      order: 4,
      when: sym ? '两端都在 NAT 后且任一端 symmetric（仅剩的直连尝试）'
                : '两端都在 NAT 后且都非对称（UDP 打洞失败/被阻断时的次选直连）',
      action: '独立信令交换 TCP 映射（不依赖同端口控制连接）+ 双端同时 connect + ≤5s 短超时，失败即回落 TURN',
      success: sym ? '低（R4 ~40% 尚为锥↔公网测得；含对称端只会更低，文献 Guha&Francis 对称类最差）'
                   : '低-中（R4 复测 ~40%，失败=映射跨连接关闭不持久）',
      timeoutMs: 5000,
      basis: '[已实测 R4 E16/E17/E18 + 文献 RFC 5382]',
    });
  } else {
    // 一端公网：TCP SO 无意义（直接 connect 即可），标注跳过
    chain.push({
      id: 'tcp-simultaneous-open',
      order: 4,
      when: '一端公网 —— 跳过（直接 connect 快车道已覆盖）',
      action: '不发起 TCP SO',
      success: '不适用',
      timeoutMs: 0,
      basis: '[推理 R4 §9.4.3]',
    });
  }

  // ⑤ TURN 兜底（始终在线）
  chain.push({
    id: 'turn-relay',
    order: 5,
    when: '始终（DCUtR 骨架，直连不中即回落）',
    action: 'A→S→B 全流量经服务器转发（复用 phase4 relay）',
    success: 'guaranteed（可达性）+ 硬约束 1 Mbps 上行 ≈120 KB/s（R3 E13 实测）',
    timeoutMs: 0,
    basis: '[已实测 R3 E13]',
  });

  return {
    chain,
    first: chain.find((c) => c.timeoutMs > 0)?.id ?? 'turn-relay',
    summary: (() => {
      if (anyPublic || anyFullCone) return '直接 connect 快车道（一端公网/全锥）→ 失败转 IPv6 直连（如有）→ UDP 打洞';
      if (bothV6) return 'IPv6 直连（两端 GUA，不依赖 v4 NAT）→ 失败转 UDP 打洞/TCP SO → TURN';
      if (bothCone) return 'UDP 打洞（锥↔锥，回打实际源）→ 失败转 TCP SO → TURN';
      if (anySymmetric) return 'UDP 判死 → TCP SO best-effort（低）→ TURN 兜底';
      return 'TCP SO best-effort → TURN 兜底';
    })(),
  };
}

// 便捷：给出「推荐首条策略 + 全链」的一句话，供日志/状态机打印
export function recommend(self, peer) {
  const r = selectStrategy(self, peer);
  return {
    summary: r.summary,
    chain: r.chain.map((c) => ({ id: c.id, when: c.when, success: c.success })),
  };
}
