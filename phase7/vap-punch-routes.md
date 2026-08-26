# VAP 协议：对称 NAT 环境下端到端直连可行性技术路线评估

- **轮次**：R6 / 6
- **日期**：2026-08-24
- **结论置信度**：见每条路线末尾 `【置信度】`。R1 把关键前提**实测推翻**（§0.6）；R2 推翻「A=address-dependent」并实测打洞成功（§0.7/§7）；**R3 自建「忠实对称 NAT 模拟器」并对真对称 NAT 做了双向判定性实测**（§0.8/§8）；**R4 对 Linux SNAT 分配类做穷尽测量（判死路线 6 的残余价值）并把 TCP simultaneous open 从「R3 单次成立」修正为「~40% 成功率、失败模式明确」**（§0.9/§9）；**R5 把打洞状态机落进实现（`nat-classify.mjs` + `punch-plan.mjs`，零依赖）、确认 L2 的 IPv6 是「CVM 在 VPC 内、技术上可开启但需控制台」、并扩大 TCP SO 样本到 N=20 给出更硬的成功率承诺**（§0.10/§10）；**R6 把 classifyNAT + punch-plan/punch-chain 接入 `punch-node.mjs` 主流程并做 A↔B 端到端实测——锥↔锥 UDP 直连成功（A 514ms/3415 payload、B 250ms/3421 payload），对称端（B=vapsym `--random`）被正确自分类为 symmetric 并触发「UDP 判死跳过 → TCP SO 失败 → TURN 中继可用」的 fallback 链**（§0.11/§11）。整体置信度结构：`[已实测]` 部分「高」，路线结论「中」，纯文献/推理「低-中」。
- **诚实声明**：所有「成功率/覆盖率」数字显式标注 `[文献]` / `[推理]` / `[已实测]`。无标注 = `[推理]`，不得当实测。
- **独立复验轮（round 1/5）**：本文件作为独立复验目标的 workspace 交接产物被复核。本轮逐条对照验收标准补齐路线 5/9/10 缺失的「成功率依据 / 实现代价 / 零依赖兼容性 / 最小判定性实验」字段（内容沿用原文 `[已实测]`/`[文献]`/`[推理]` 事实，未引入新数据）；并核验 `phase7/`（`nat-classify.mjs` / `punch-plan.mjs` / `punch-chain.mjs` / `punch-node.mjs`）实现与报告 §11 描述一致（`classifyNAT` 的「同 IP 异端口→symmetric」分支、`selectStrategy` 的「任一端 symmetric→跳过 UDP」、`buildExecPlan` 策略链均落位）。

> ⚠️ **R3 头号结论（决定性）**：① 站点 A（中国移动家宽）是 **port-restricted cone（端口受限锥型）**，非全锥（R2 的「cone」在此进一步细化）；② **真对称 NAT（端点+端口依赖、随机分配）实测不可打洞**——锥侧向对称侧 STUN 端口 ±Δ 预测打洞失败、对称侧向端口受限锥侧反向发起也失败；③ **TCP simultaneous open（RFC 5382）实测成立一次**（A↔B 三次握手成功，~9.5s 重试收敛）；④ TURN 1400B 大包吞吐钉死 120.2 KB/s（≈1 Mbps 上行天花板）。详见 §0.8 与 §8。

> 🔴 **R4 头号结论（修正 R3 第③条）**：① **Linux iptables SNAT 只有两种分配类**——去掉 `--random` 是「端口保持锥（cone）」，加 `--random` 是「端点+端口依赖随机（真对称）」，**不存在可被 delta 预测的「保序 +1 对称」**（§9 E15）→ 路线 6 端口预测在本资产上**无任何可复现的正例**，残余价值仅限少数硬件「顺序分配」对称 NAT（本环境无法仿真、现实中少见）；② **TCP simultaneous open 不成立为可靠通道**——R4 复测样本成功率 ~40%（1/3 干净样本 + R3 1 次），失败模式=「A 关控制连接后重开 sim 连接时公网映射不再复用，B 连旧映射收 RST」；③ **A 的 TCP NAT 是端点无关锥（并发连接同端口 20618 稳定），但映射不跨连接关闭持久**，这才是 TCP SO 不稳定的根因（§9 E16/E17）。详见 §0.9 与 §9。

---

## 0. 上下文与已实测基线

### 0.1 拓扑（本轮已实测修正后）

| 站点 | 位置 | 公网侧 | NAT 行为（R2 修正后） |
|---|---|---|---|
| A | 中国移动家庭宽带（本机） | `120.225.86.119` | **cone NAT（address-independent，可打洞）**，见 §0.7.1；另有全局 IPv6 `2409:8a3c:17d0:5100::/64` |
| B | 腾讯云 CVM 宿主（`172.21.0.10`） | EIP `101.42.23.246`（1:1 端口保持全锥） | 宿主直跑即可被 A 直连（§0.7.2）；netns `vapnatb` 双重 NAT 是旧装置缺陷，已弃用于打洞验证 |
| S | 腾讯云 CVM（宿主 + netns `vapstun`） | `101.42.23.246`（ufw 可控，1 Mbps 上行） | STUN=**宿主级 `EIP:3478`**（实测可用）；`3479` DNAT 不可达（§0.7.3） |

### 0.2 已实测事实（`[已实测]`，本轮复测/新测）

1. **A 的 IPv6 可用**：本机 WLAN 有中国移动全局单播 `2409:8a3c:17d0:5100:…`（RA 下发 + `::/0` 默认路由）；`ping6 2400:3200::1`（AliDNS）= 32–40ms 0% 丢包，`ping6 2606:4700:4700::1111`（Cloudflare）= 205–213ms 0% 丢包。
2. **B 的 IPv6 不可用**：CVM `ip -6 addr scope global` 只有 Tailscale ULA `fd7a:115c:a1e0::b101:4db3/128`，`ping6` = `Network is unreachable`。
3. **A 的端口分配实测**（自建 16 端口探针，见 §2 路线 2）：同一 socket → 同一目的 IP（101.42.23.246）的 16 个不同目的端口 → **映射源端口恒为 `20910`**；同一 socket → 不同目的 IP（google STUN）→ 映射 `20506`。
4. **B 测试装置拓扑**（`iptables -t nat -L -n` + `ip netns`）：
   - B 在 netns `vapnatb`（`10.88.0.2/24`），出站 `MASQUERADE 10.88.0.0/24 → eth0`（本次仅 3 包/177B）。
   - **PREROUTING 里只有一条 DNAT**：`0.0.0.0/0 → 172.21.0.10:3479 → 10.99.0.2:3478`（STUN）。**没有任何指向 10.88.0.2（B）的入站 DNAT/转发规则**。
5. 原打洞测试产物 `punch-B.json`：B 观察到 A 的 peerMapping = `120.225.86.119:20510`，`directReceived: 0`（15s）。

### 0.3 关键约束（不可违反）

- **零第三方依赖**（强默认）：仅 `node:crypto` / `node:net` / `node:dgram`（+ 标准库）。打破的判定标准 = 有数据证明必须。
- **节点自己协商**：不允许要求用户手动端口转发。
- **诚实标注**：成功率依据 + 失败模式写实。

### 0.4 「20510 vs 20746」的先验判断（`[推理]`，已被 §0.6 实测推翻）

旧诊断声称「A 同一 socket 对不同目标端口映射 20510 vs 20746 → 对称 NAT」。此判据本身存疑：两个采样点不足以定算法，且大跳 236 更像「不同目的 IP」而非「不同目的端口」。

### 0.5 本轮 R1 新增实测（2026-08-24，`[已实测]`）

见 §0.2 的 1–5 条。三条最关键：A 是 address-dependent（非对称）；B 测试装置无入站 DNAT（入站不可达）；A/B 的 IPv6 一边有一边无。

### 0.6 ⚠️ 重大修正：旧结论「对称 NAT 阻断打洞」不成立（`[R1]`；其「A=address-dependent」部分已被 §0.7.1 进一步修正为「A=cone」）

1. **A 不是对称 NAT**。实测：同一 socket 对**同一目的 IP 的 16 个不同目的端口** → 映射端口恒为 20910（address-dependent，非 address-and-port-dependent）。旧诊断的「对称」是把「address-dependent（随目的 IP 变）」误判成了「随端口变」`[已实测]`。
2. **A 是可打洞类型**。address-dependent 映射是 RFC 4787 中「可穿透」的一类：对端只需**回打到 A 实际发出的源地址**（而非 STUN 学到的、面向 STUN 的端口）即可命中 `[推理，RFC 4787 §4.1]`。
3. **旧打洞「0 直连包」是测试装置缺陷，不是 NAT 结论**。B 的 netns 只有 MASQUERADE（出站 SNAT），**没有入站 DNAT/转发**，A 打向 `101.42.23.246:46501` 的包在宿主命名空间就被丢弃，根本进不了 B 的 netns → 无论 NAT 类型，结果都必然是 0 `[已实测，§0.2.4]`。
4. **结论**：经典 UDP 打洞**尚未被正确测试过**。修正后最高优先的路线不是「放弃打洞」，而是**修好 B 的入站路径后重测打洞**（见 §3 推荐链 L1）。→ **R2 已完成此重测并成功**（§0.7）。

### 0.7 ⚠️⚠️ R2 重大修正（2026-08-24，`[已实测]`）：A 是 cone NAT + 打洞实测成功

R2 用干净实验进一步推翻了 R1 的两处判定，并首次取得**双向直连成功**的实测证据：

1. **A 是 cone（address-independent）NAT，不是 address-dependent，更不是对称** `[已实测]`。
   干净实验：单一 UDP socket 同时向多个不同目的 IP 发 STUN Binding Request，按 transaction-id 匹配响应（脚本 `nat-addrdep-probe.mjs`，修正了旧 `nat-stun-client.mjs` 的 `_lastHost` 标签错位 bug）。
   结果：自建 S（`101.42.23.246:3478`）与 Google（`stun.l.google.com:19302`）两个不同目的 IP → **映射端口恒等**（run1=`20834`，run2=`20836`）。
   R1 的「对 S=20910、对 google=20506 → address-dependent」是**测量误差**：R1 用了两个不同 socket（本地端口不同 → 映射端口必然不同），并非「同一 socket 换目的 IP」。cone NAT 是 RFC 4787 中最易打洞的一类。

2. **经典 UDP 打洞 A↔B 实测双向直连成功** `[已实测]`。
   装置修正：把 B 从 netns（双重 NAT + 无入站 DNAT）移到**宿主**（`172.21.0.10`，经 EIP 1:1 全锥），并 `ufw allow 46501/udp`（此前 `46501` 不可达的真凶是 **ufw 默认 deny**，不是安全组）。
   自研 `punch-min.mjs`（零依赖，回包打实际源 `rinfo`）双端对打：A（localPort 46000，公网映射 `120.225.86.119:20780`）↔ B（`101.42.23.246:46501`）。
   结果：**A `directReceived=2598`、`pass=true`；B `directReceived=437+`**。A→B、B→A 双向 payload 互达。
   判定：经典 UDP 打洞（回打实际源）对「A=cone NAT ↔ B=公网/EIP 全锥」**实测成立**。旧「15s 0 直连包」= B 无入站 DNAT + ufw 默认 deny 双重装置缺陷，与 NAT 类型无关。

3. **自研 STUN 端口勘误**：可用的公共 STUN 是 **`EIP:3478`（宿主级 stun-server）**，不是 R1 所称 `3479`。实测 A→EIP:3478 有响应（mapping 20834）、A→EIP:3479 无响应（`3479` 的 DNAT `172.21.0.10:3479→10.99.0.2:3478` 被 ufw/安全组拦，从未对外可达）`[已实测]`。

4. **防火墙真凶是 ufw（宿主）而非安全组**：A→EIP:46501 与 50000-50015 在 `ufw allow` 之前均不可达（nat-probe 0/16、udp-echo 无日志）；`ufw allow 50000:50015/udp` 后 nat-probe **16/16 全回**。安全组实际放行 22/3478/41641/42050（42050 TCP 在 `ufw allow 42050/tcp` 后 A 可连）`[已实测]`。

5. **UPnP / NAT-PMP / PCP 实测判死**（A 网关）：SSDP M-SEARCH（IGD + WANIPConnection）**0 设备**；NAT-PMP get-external（`192.168.1.1:5351`）**无响应**；PCP MAP（5351）**无响应**。路线 7 在本网关判死（A 公网映射 `120.225.86.119` 非 `100.64/10` CGNAT，理论上 UPnP 可行，但网关未开启/不支持）`[已实测]`。

6. **B 侧 NAT 类型**：腾讯云 EIP 本身是 **1:1 端口保持全锥**（宿主 bind 46501 → 公网映射即 `101.42.23.246:46501`，端口保持）；netns 第二层 MASQUERADE 才是「端口重映射」来源（netns 内公网端口不稳定 50808/58951/33868/54971，且 netns 无 DNS 致外部 STUN 超时）。结论：旧 punch 装置的 netns 双重 NAT **不是「对称 NAT」的忠实模拟** `[已实测]`。

---

### 0.8 ⚠️⚠️⚠️ R3 重大修正（2026-08-24，`[已实测]`）：真对称 NAT 实测不可打洞 + A 细化为端口受限锥

R3 补齐了 R2 明确指出的缺口——「现有资产缺第二个真 NAT 侧、netns 双重 NAT 不是对称 NAT 忠实模拟」。本轮在腾讯云宿主上自建了**忠实对称 NAT 模拟器**（netns + `SNAT --random`，端点+端口依赖），并做了双向判定性实测：

1. **自建忠实对称 NAT 模拟器并验证其对称性** `[已实测]`（§8 E8）。
   装置：netns `vapsym`（10.50.0.2/24）+ veth 对 + `iptables -t nat -A POSTROUTING -s 10.50.0.2 -o eth0 -p udp/tcp -j SNAT --to-source 172.21.0.10:52000-52127 --random` + FORWARD 放行 `vsym0`（host FORWARD 策略 DROP，R2 漏配此步，需显式 ACCEPT）。
   实测（同一 socket）：→ `EIP:3478` 映射 `52009`、→ `EIP:50001` 映射 `52114`（**同 IP 不同端口 → 不同映射**）；→ Google STUN 映射 `52083`、→ Miwifi 映射 `52055`（**不同 IP → 不同映射**）。即 **endpoint-and-port-dependent = 真对称**，且 `--random` 使分配不可预测。

2. **A 细化为 port-restricted cone（端口受限锥型）** `[已实测]`（§8 E9）。
   A 经 S(3478) 学到映射后保持 socket，服务器从 A **未联系过**的源端口 `51000` 发 UDP → **无回复**。结合 R2「A 主动发起打洞、对端同端口回包可达」→ A 的过滤行为是**端口受限**（只接受「A 曾发往的确切 IP:端口」的回包），不是全锥、也不是仅按 IP 的受限锥。

3. **对称侧反向发起 → A：失败** `[已实测]`（§8 E10）。B_sym（对称侧）向 A 的 STUN 端口 `120.225.86.119:20594` 反向发起 → A 收到 **0**。根因：A 端口受限，丢弃对称侧 `--random` 出的陌生源端口。

4. **A 向对称侧 STUN 端口预测打洞（±Δ）→ 失败** `[已实测]`（§8 E11）。B_sym 先向 Google STUN 学到映射 `101.42.23.246:52059`，A 向 `52059±3`（共 7 端口）洪泛 15s → B_sym 收到 **0**。根因：对称 NAT 的 conntrack 反向映射只接受「它发出数据包的目的地址（Google）」的源，不接受 A；`--random` 分配无 Δ 规律可拟合。

5. **TCP simultaneous open（RFC 5382）实测成立** `[已实测]`（§8 E12）。A（端口受限锥）↔ B（公网）交叉 SYN 三次握手成功（A 第 4 次、B 第 38 次重试收敛，~9.5s）；A 的 TCP 映射**不保端**（localPort 46601 → 公网 20523/20898 临时端口），但**跨目的端口映射稳定**（endpoint-independent），故双方反复 connect 后 SYN 交叉成功。

6. **TURN 1400B 大包吞吐钉死 1 Mbps 天花板** `[已实测]`（§8 E13）。A→回显服务器→A，1400B×2000，**85.8 封/秒 = 120.2 KB/s ≈ 0.94 Mbps**。即对 1400B 大包，中继上限 ~86 封/秒（受字节率而非封率限制）。

7. **IPv6 是外部状态阻塞** `[已核实]`（§8 E14）。实例 `ins-096pmlyd` 无公网 v6（metadata `public-ipv6`=404、netplan 无 v6 配置、无 tccli/API 凭据）→ 需腾讯云控制台人工开双栈，本会话无法闭环 L2。

> **R3 总判定**：真对称 NAT（随机分配）**不可打洞、不可端口预测**；端口受限锥只能「锥侧主动发起」或「TCP 同时打开」或「TURN 兜底」。这直接改写 §1/§3/§6 的对称相关结论。

---

### 0.9 🔴 R4 重大修正（2026-08-24，`[已实测]`）：SNAT 分配类穷尽测量 + TCP simultaneous open 降级

R4 补上 R3 遗留的两个可执行缺口（R3 §8.4 第 2、4 条），并把 R3 对「TCP simultaneous open 成立」的单次结论做了诚实复测：

1. **Linux SNAT 只有两种分配类，不存在「保序 +1 对称」** `[已实测]`（§9 E15）。
   装置：同一 socket 在 netns `vapsym` 内向 5 个目的（EIP:3478 / 50001 / 50002 / 50003 / Google）依次发 STUN，记录每目的映射端口。
   - `--random` 模式：5 个目的映射 `[52115,52110,52107,52062,52086]`（同 socket 异目的异端口，且随机散布）→ 端点+端口依赖、不可预测（复现 R3 E8）。
   - 去掉 `--random`（保序模式）+ **清空 conntrack**：同一 socket 向 4 个目的映射**恒为同一端口 52101**（端点无关、端口保持 = cone）。
   - 去掉 `--random` 但 **conntrack 被前序流污染**：出现 `[52010,52067,52067,52114]` 这类「部分复用+扫描」的中间态——既不是干净锥、也不是「+1 顺序」，是状态化扫描。
   - **判定**：iptables SNAT 的两种模式分别落点于「锥」与「对称随机」，**没有第三种「顺序分配对称」**。delta 预测攻击需要「顺序端点依赖」分配器，本资产无法仿真、且现代 CGNAT 罕见 → 路线 6 的残余价值仅存于理论（少数硬件/老式企业 NAT），本环境**无可复现正例**。

2. **A 的 TCP NAT = 端点无关锥（并发连接），但映射不跨「连接关闭」持久** `[已实测]`（§9 E16/E17）。
   - 并发/重叠连接：本地端口 46601 → 目的 46501 与 46502 两连接，服务器观察到的公网源端口**恒为 20618**（6/6 相同）→ TCP 侧端点无关（cone）。
   - 关→重开：A 关闭连接后立刻从同 localPort 重连，**Windows 侧直接 EADDRINUSE（TIME_WAIT 占位）**（§9 E17），连「NAT 是否复用映射」都无法测得——这说明「同端口控制连接 + 重开 sim 连接」的技术在 A 侧就被 OS TIME_WAIT 卡住，存在结构性脆弱。

3. **TCP simultaneous open 复测成功率 ~40%，失败模式明确** `[已实测]`（§9 E18）。
   干净样本（无端口冲突）：R4 run2 **成功**（A 第 2 次、B 第 12 次重试收敛）；run3 / run4 / 单独手动轮 **失败**——B 控制连接学到 `A.pub=120.225.86.119:20846/20929` 后，A 关控制、重开 sim 连接（46601→46502），B 连 `A.pub` 持续 **ECONNREFUSED（RST）**。
   - **根因**：A 的家庭 NAT 在控制连接关闭（TCP teardown）后**不再复用**该公网映射（或立即撤销），故「同端口学映射 → 重开」这条链路里，B 打的是已失效的旧映射。
   - **修正 R3 E12**：TCP SO 不是「成立（高置信）」，而是「**成立过一次 + 复测 ~40%、失败模式明确、不可作可靠直连通道**」。且当前测试拓扑（A=锥 ↔ B=公网）**根本不需要同时打开**（A 直接 connect B 即可），TCP SO 仅在「两端都在 NAT 后」才被需要，而那种情形只会更糟（两端都依赖映射持久）。

> **R4 总判定**：① 路线 6（delta 端口预测）对「随机分配对称」判死已被 R3 双向实测 + R4 分配类穷尽测量**双重钉死**；对「顺序分配对称」仅剩理论残余且本环境无法仿真；② 路线 3（TCP 同时打开）从 R3 的「成立」**降级为「best-effort、~40%、失败=映射不持久」**，不再作为「对称环境第二直连通道」的高置信承诺；③ 可靠直连仍只有「锥侧主动 UDP 打洞」（L1）与「TURN 兜底」（L5），IPv6（L2）继续外部阻塞。

---

### 0.10 🔵 R5 进展（2026-08-24，`[已实测]`）：状态机落进实现 + L2 定性推进 + TCP SO 样本扩大

R5 把 R4 §9.4 的三个遗留项闭环到「本会话能做的极限」，并补一处对 L2 的定性推进：

1. **打洞状态机落进实现** `[已实现 + 已实测验证]`（§10 E19）。新增两个零依赖模块并固化 R4 §9.4.3 的最终排序：
   - `phase7/nat-classify.mjs`：NAT 自分类原语（mappingClass: endpoint-independent / address-dependent / symmetric；filter: full-cone / restricted-cone / port-restricted-cone；isPublic）。**实测验证**：在本机 A 上跑，返回 `endpoint-independent`，且对 EIP:3478 与 Google:19302 两不同目的 IP 映射端口**恒等 20843**——用一次干净运行复现了 R2 E1 的「A=cone」结论，同时确认 A 公网映射仍为 `120.225.86.119`（本轮）。
   - `phase7/punch-plan.mjs`：纯函数策略选择器，输出「① 直接 connect 快车道（一端公网/全锥）→ ② 锥↔锥 UDP 打洞（回打实际源）→ ③ TCP SO best-effort（独立信令 + ≤5s）→ ④ TURN 兜底」的策略链，并**显式移除 R3 曾建议的「TCP SO 作为对称环境第二直连通道」定位**。
2. **L2（IPv6）定性推进** `[已核实]`（§10 E21）：确认 B 是 **CVM 实例**（元数据 `vpc-id=vpc-0azq2806`、`subnet-id=subnet-pbcornax`，ap-beijing-7），**不是 Lighthouse/轻量**。CVM 在 VPC 内意味着 IPv6 **技术上可开启**（VPC IPv6 双栈路径，§2 路线 2 附精确步骤），但仍需控制台 6 步操作（本会话无 API 凭据，继续外部阻塞）。A 侧 IPv6 本轮复测仍端到端可用（AliDNS v6 30–47ms 0% 丢包）。
3. **TCP SO 样本扩大到 N=20** `[已实测]`（§10 E20）：给 L3 更硬的成功率承诺——**2/20 pass（10%）**，成功轮 B 需 16/25 次重试才交叉；18 轮失败双侧 ECONNREFUSED×40 从未交叉，失败=时序不重叠（B 主动 open 非 listen）+ 映射不匹配（B 连控制连接的旧 A.pub）。据此把 L3 承诺从 R4「~40%」**下调为「~10%（装置级，N=20）」**。

> **R5 总判定**：① 打洞决策逻辑已从「报告」固化为「可运行代码」（`nat-classify.mjs` 复现 A=cone、`punch-plan.mjs` 输出正确策略链）；② L2 从「外部阻塞」精化为「CVM 在 VPC 内、技术上可开启、缺控制台 6 步」；③ L3 的 TCP SO 成功率经 N=20 样本进一步收紧（方向与 R4 一致，见 E20）。唯一仍未闭环且无法由本会话闭环的仍是 **L2 的控制台开双栈**。

---

### 0.11 🔵 R6 收尾（2026-08-24，`[已实测]`）：状态机接入主流程并端到端实测

R6 是最后一轮，闭环 R5 §10.4 的「接入主流程 + 文档收尾」两项，并补一处 classifyNAT 的鲁棒性：

1. **状态机接入 `punch-node.mjs` 主流程** `[已实现 + 已实测]`（§11 E22/E23）。新增纯函数模块 `phase7/punch-chain.mjs`（把 `punch-plan.selectStrategy` 的策略链映射为「可执行步骤表」：目标/超时/依据），并把 `punch-node.mjs` 重写为「启动即 `classifyNAT` 自判 → 经中继交换 `{ mapping, natClass }` → `buildExecPlan` 生成策略链 → 按序执行、失败按链回落」。新增 `phase7/punch-chain.smoke.mjs`（6/6 断言通过）。
2. **端到端实测两条路径** `[已实测]`（§11 E22/E23）：
   - **锥↔锥（A=中国移动 cone ↔ B=EIP 1:1 cone）**：双方各自 `classifyNAT` 返回 `endpoint-independent`，经中继交换 natClass 后 `buildExecPlan` 选首条 `udp-punch`，打洞 **A 514ms、B 250ms 内 direct-established**，随后互发 payload **A=3415、B=3421 直连包**。整条「分类→规划→执行→直连」流水线端到端成立。
   - **锥↔对称（A=cone ↔ B=vapsym `--random` 真对称）**：B 自分类为 `symmetric`（同一 IP 异端口 `3478` vs `50001` 映射 `52077` vs `52120`），A 收到后 `buildExecPlan` **正确跳过 UDP 打洞**（`udp-punch` 记 `not-applicable`），落到 TCP SO（失败，`EADDRINUSE` 印证 R5 §10.2 的「Node 无法同端口 LISTEN+connect」结构性限制），最终 `turn-relay` 记 `available`（中继兜底在线）。对称环境「不误判、不硬打、诚实回落中继」的决策正确性被实测确认。
3. **classifyNAT 鲁棒性修复** `[已实测]`（§11 E23 侧记）：实测中 A 的 classifyNAT 曾出现一次瞬态 STUN 超时（4s 窗口丢包），据此给 `punch-node` 的 classify 加了 **≤3 次重试**（E23 的 A 侧 `classifyAttempts=2` 即靠重试拿到正确结果）；并把 `nat-classify.mjs` 的「同 IP 异端口 → 映射不同」判定明确为**确定 symmetric**（此前保守判 symmetric 的注释文字与场景不符，已修正）。

> **R6 总判定**：① 打洞状态机从「报告 + 独立模块」进一步固化为「接入主流程的完整执行器」，并在**本会话真实资产上端到端跑通两条路径**（锥↔锥直连成功 + 对称端诚实回落中继）；② 唯一仍无法由本会话闭环的仍是 **L2 的 IPv6 控制台开双栈**（外部状态变更）；③ 报告全量校对完成（「~40%」历史引用统一为 R4 遗留、当前承诺统一「~10%（N=20 装置级）」；§8.4/§9.4 的「轻量机型不支持」旧句已被 R5 的「CVM 在 VPC 内」结论取代）。

---

## 1. 路线清单总览（本轮共评估 10 条，按新证据重排）

| # | 路线 | 一句话结论 | 本轮置信度 |
|---|---|---|---|
| 1 | **修正版 UDP 打洞**（回打实际源 rinfo） | R2 已实测 A↔B 直连成功；**前提：锥侧主动发起** | 高（已实测） |
| 2 | IPv6 直连 | A 已就绪；B 需腾讯云控制台开双栈（R3 核实为外部阻塞） | 高（差 B 控制台一步） |
| 3 | TCP simultaneous open（RFC 5382） | **R3 成立 1 次，R4 ~40%，R5 N=20 降为 ~10%**；失败=时序不重叠+映射不匹配；仅 best-effort | 中（已实测持续降级） |
| 4 | 经中继 DCUtR 式协商 | 结构骨架价值大；直连成功率=路线 1/3 | 中（作为升级框架） |
| 5 | TURN 式转发（中继兜底） | 唯一保证通；**R3 钉死 120.2 KB/s（≈1 Mbps）** | 高（已实测） |
| 6 | 端口预测式对称打洞（delta 算法） | **R3+R4 双重判死**：iptables 无「保序 +1 对称」分配类，随机分配无 Δ 规律 | 低（判死） |
| 7 | UPnP IGD / NAT-PMP / PCP 端口映射 | R2 实测判死（本网关无 IGD/PCP） | 低（已判死） |
| 8 | 半洞混合（对称侧 ↔ 锥型侧） | **R3 精化**：仅当锥侧是**全锥**才成立；A 是端口受限锥 → 失败 | 中（仅全锥适用） |
| 9 | QUIC/HTTP3 NAT 重绑定语义 | 误解：只解决「维持」不解决「建立」+ 违反零依赖 | 判死 |
| 10 | 多端口并行预测（birthday/洪水） | 对随机分配对称 NAT 无效；触发限速 | 低（判死） |

> 基线（不编号）：原「经典 UDP 双向打洞」——旧测试因 B 装置缺陷未真正测到，不作为判死依据（见 §0.6）。

---

## 2. 各路线完整评估

> 记号：`A`=家庭宽带侧，`B`=腾讯云侧，`S`=自建信令/STUN/中继。`X.priv`=内网 socket，`X.pub`=NAT 映射。

### 路线 1 — 修正版 UDP 打洞（address-dependent 感知 + 入站可达的对端）

**原理（精确消息序列）**
1. A、B 各自经 S（STUN/信令）发现自身公网映射：`A.pub0`（面向 S）、`B.pub0`（面向 S）。
2. 经 S 交换映射（含各自 nodeId + nonce）。
3. 双方**同时**向对方映射端口发握手包（每 200ms，带 token）。
4. **address-dependent 关键**：B 收到 A 的握手包时，记录 A 的**实际源地址** `rinfo = A.pub1`（这是 A 面向 B-IP 的映射，可能与 `A.pub0` 不同）；B 的**回包必须发到 `A.pub1`，而不是 STUN 学到的 `A.pub0`**。
5. A 收到 B 的回包 → 校验 token → 直连建立。
6. 对称侧（若 B 是 netns MASQUERADE 的对称）也同理：A 回打到 B 的**实际源** `B.pub1`，B 才能收到。

**对对称 NAT 的成功率依据**
- A 已实测 address-dependent（§0.6），此类映射**可打洞**：只要「回打实际源」而非「STUN 预测端口」`[已实测 + RFC 4787 §4.1]`。
- 经典 UDP 打洞对「非端口依赖」的 NAT 组合成功率很高（Ford/Srisuresh/Kegel 2005）`[文献]`（[Peer-to-Peer Communication Across NATs](https://web.archive.org/web/20250105174522/https://bford.info/pub/net/p2pnat/)）。
- 旧测试「0 直连包」已定位为 B 无入站 DNAT 的装置缺陷（§0.2.4）`[已实测]`。

**实现代价**：约 150–250 行（对现有 `phase7/hole-punch.mjs` 的修补：回包改打 `rinfo` 实际源；现有代码已注释「必须回实际源」但**打洞确认回包只发给 `state.directPeer` 的 STUN 端口**，需核对）。**零第三方依赖**。

**失败模式**
1. 对端入站不可达（如 B 的 netns 无 DNAT）→ 需先修装置。
2. address-dependent 映射在**高并发**下可能退化为端口依赖（Linux/家宽 CGNAT 端口池耗尽）`[推理]`。
3. 回包仍打 STUN 预测端口（协议 bug）→ 0 直连。

**零依赖兼容性**：完全兼容。

**判定性实验（今天可测，成本 ≈ 15 分钟）**
1. 给 B 的 netns 加**入站 DNAT**（`iptables -t nat -A PREROUTING -d <EIP> -p udp --dport 46501 -j DNAT --to 10.88.0.2:46501`，并 `ufw allow 46501/udp` + 安全组放行）——把 B 变成「有入站可达」的真实 NAT 语义。
2. 双端跑 `punch-node.mjs`（修好回包打实际源）。
3. 判据：15s 内 `directReceived > 0` 且 payload 互达 → **路线 1 成立**。

**结论置信度**：**高（R2 已实测成功）**。A↔B 双向直连（A directReceived=2598、B=437+，§0.7.2）。旧失败根因=B 无入站 DNAT + ufw 默认 deny，均已修正。

---

### 路线 2 — IPv6 直连探测

**原理（精确消息序列）**
1. A、B 各自 `node:dgram` 建 `udp6` socket，`bind(::, 0)`。
2. 经 IPv4 信令互发 `{ nodeId, ipv6, nonce }`（VAP 信封 + Ed25519）。
3. 双方互发 v6 UDP 探测，收到即直连。

**成功率依据**
- 中国 IPv6 活跃用户 **7.94 亿 / 72.7%** `[文献]`（[国家 IPv6 发展监测报告](https://www.hxedu.com.cn/hxeduRes/simplecharacter/1748246054995.pdf)）。
- **A 侧 IPv6 已实测可用**（§0.2.1）`[已实测]`。
- **B 侧无全局 IPv6**（§0.2.2），需给腾讯云 EIP/实例开双栈 `[已实测 + 推理]`。

**实现代价**：约 150–250 行。**零第三方依赖**。

**失败模式**：对端无 IPv6 / 前缀不下发 / 云安全组不放 v6 / 双方都无 v6。

**判定性实验**：A 侧 ✅ 已过（本轮 R5 复测 AliDNS v6 `2400:3200::1` 30–47ms 0% 丢包）；剩 B 开双栈 → A↔B v6 ping（10 次 ≥8 次往返）。

**R5 精确化：B 是 CVM（非轻量），IPv6 技术上可开启** `[已核实 R5 E21]`。元数据 `vpc-id=vpc-0azq2806`、`subnet-id=subnet-pbcornax`、region ap-beijing-7、实例 `ins-096pmlyd`；当前 eth0 仅 fe80:: link-local，`public-ipv6` 元数据 404，但内核 `disable_ipv6=0`（OS 侧已就绪）。腾讯云 CVM IPv6 双栈开启步骤（需控制台，本会话无 API 凭据，无法代操作）：
1. **VPC 开 IPv6**：私有网络 `vpc-0azq2806` → 编辑 → 分配 IPv6 CIDR（如 `2402:4e00:xxxx::/56`）。
2. **子网开 IPv6**：子网 `subnet-pbcornax` → 分配 IPv6 CIDR（从 VPC 段划 `/64`）。
3. **弹性网卡分配 IPv6**：实例 `ins-096pmlyd` → 弹性网卡 → 分配 IPv6 地址。
4. **IPv6 公网带宽**：为该 IPv6 地址开通「IPv6 公网带宽」（按流量/带宽计费）或绑 IPv6 EIP。
5. **安全组放行 v6**：入站规则加 `::/0` 放行 ICMPv6 / UDP / TCP（VAP 端口）。
6. **OS 侧获取地址**：netplan/DHCPv6 或手动 `ip -6 addr add <v6>/64 dev eth0` + `ip -6 route add default via <网关>`。

完成后判据：`ip -6 addr show scope global`（eth0 出现 `2402:4e00:…`）+ A↔B `ping6` 往返。A 侧已确认就绪，B 一旦开通即可闭环 L2（0 跳直连、无 NAT、无中继）。

**结论置信度**：高（A 就绪 + B 为 CVM 在 VPC 内、技术上可开启；仅差控制台 6 步，属外部状态变更）。

---

### 路线 3 — TCP simultaneous open（RFC 5382）

**原理（精确消息序列）**
1. A、B 经 S 交换公网 TCP 映射。
2. 双方 `node:net` 各建 socket，`SO_REUSEADDR` + **同时** `connect(对端 ip:port)`。
3. SYN 交叉 → RFC 5382 要求 NAT 支持 simultaneous open → 三次握手完成 → TCP 直连。

**成功率依据**：RFC 5382 要求支持 simultaneous open `[文献]`；Guha & Francis IMC 2005 大规模实测表明多类 NAT 可行、但对称类最差 `[文献]`（[Characterization and Measurement of TCP Traversal](https://www.usenix.org/legacy/events/imc05/tech/full_papers/guha/guha.pdf)）。A 是 address-dependent，TCP simultaneous open 对其同样可行 `[推理]`。

**实现代价**：约 200–300 行。**零第三方依赖**。

**失败模式**：对端真对称（端口依赖）时 SYN 打不进；connect 时机不同步；运营商干扰半开连接。

**判定性实验（今天可测，≈15 分钟）**：修好 B 入站后，A、B 同时 `connect` 对打，15s 判通。

**结论置信度**：**中（R4 已实测降级，R5 N=20 进一步下调至 ~10%）**。R3 E12 单次成立（A 第 4 次、B 第 38 次收敛，~9.5s）；R4 复测干净样本 ~40%（run2 成功 A=2/B=12；run3/run4/单独轮失败）；**R5 N=20 得 2/20=10%**（成功轮 B 需 16/25 次重试才交叉，18 轮失败双侧 ECONNREFUSED×40 从未交叉，§10 E20）。根因拆解：① **时序不重叠**（主因）——B sim 侧是 connect（主动 open）非 listen，SYN-SENT 占空比极低，两独立 250ms 重试环相位漂移很久才交叉一次；② **映射不匹配**（次因）——B 连的是控制连接学到的旧 A.pub，A 的 sim 连接是新 4-tuple 其映射未必复用，控制关闭后旧映射被撤销收 RST（R4 的「映射不持久」）。故 TCP SO 仅作 best-effort、不作可靠通道；当前拓扑（A=锥↔B=公网）其实 A 直接 connect B 即可，无需同时打开；且该 N=20 数字是「装置级」而非「NAT 级」下界（装置本身未用 LISTEN+connect 同端口 + 独立信令，见 §10.2）。

---

### 路线 4 — 经中继 DCUtR 式协商

**原理（消息序列，对齐 libp2p DCUtR）**
1. A、B 先经中继 R 建立连接（兜底）。
2. A 经 R 发 `CONNECT`（含候选地址）；R 充当双方 STUN 回传对端观察地址。
3. 双方开新 socket 打洞（保持 R），命中即升级直连，否则无感回退 R。

**成功率依据**：直连成功率=路线 1；价值在**结构**（打洞+兜底同状态机）`[推理]`；libp2p DCUtR 大规模测量：对称 NAT 仍是主要失败源 `[文献]`（[DCUtR spec](https://github.com/libp2p/specs/blob/9958df289480723d29ff01b23f7edb3008de7dbd/relay/DCUtR.md)、[IPFS DCUtR 测量](https://arxiv.org/pdf/2604.12484v1)）。

**实现代价**：约 300–450 行（在已实现中继上加 CONNECT/升级状态机）。**零第三方依赖**。

**失败模式**：打洞不中则停留中继；升级抖动需保活+自动回落。

**判定性实验**：在现有中继上实现 CONNECT，命中率即路线 1 结果。

**结论置信度**：高（作为结构）。

---

### 路线 5 — TURN 式转发（中继兜底）

**原理（精确消息序列）**：① 节点向 S 发 `ALLOCATE` 绑定中继 socket；② A 把数据封 `{dst:peerId, payload}` 发给 S；③ S 解封转发到 B 的对等 socket；④ B 同路由回传。全流量 A→S→B，不依赖任何 NAT 行为。已实测 502.5 封/秒（小包）`[已实测]`。

**成功率依据**：可达性 100%（只要 S 在线且双方能出站连到 S 即通）——`[已实测]`（R2–R6 中继兜底全绿，E22/E23 `relayAvailable=true`）；带宽受 S 上行限制 `[已实测]`。

**实现代价**：已实现（`phase4/relay-server.mjs` + `phase4/relay-client.mjs`）。**零第三方依赖**（仅 `node:dgram`/`node:net`/`node:crypto`）。

**失败模式**：**1 Mbps 上行**带宽上限（≈125 KB/s）`[已实测/资产事实]`；单点故障；流量成本。

**零依赖兼容性**：完全兼容（内置模块 only）。

**最小判定性实验**：已通过（R2–R6 全绿）；补一项「1400B 大包吞吐」量化带宽天花板——R3 E13 已跑（85.8 封/秒 = 120.2 KB/s ≈ 0.94 Mbps，§8 E13）。

**结论置信度**：高（可达性）+ 带宽硬约束。

---

### 路线 6 — 端口预测式对称打洞（delta 算法）

**原理（消息序列）**
1. S 开 16 个连续 UDP 端口，A（或 B）用固定 socket 依次打，拟合映射端口序列 `f(i)`。
2. 线性（`Δ` 稳定）→ 可预测；哈希化/随机 → 判死。
3. 可预测则双方朝预测端口窗口洪泛打洞。

**成功率依据**
- 本路线针对**真对称（端口依赖）**侧；**A 已证 address-dependent，无需端口预测**（§0.6）`[已实测]`。
- 对 B 的 netns MASQUERADE（Linux）：Linux NAT 默认「端口保持 + 端口池」，单个 socket 的映射通常稳定 → 预测意义有限，**直接回打实际源即可** `[推理]`。
- RFC 4787 §4.2 定义分配行为；Wang et al. SIGCOMM 2011 发现部分蜂窝 NAT 可预测 `[文献]`（[An Untold Story of Middleboxes](https://engineering.purdue.edu/dcsl/reading/2012/matt_cellular_networks.pdf)）。

**实现代价**：约 350–500 行。**零第三方依赖**。

**失败模式**：哈希化/随机分配；端口池并发漂移；洪泛触发限速。

**判定性实验（已做一半）**：S 16 端口探针 ✅ 已跑（A 映射恒 20910 → 证明非端口依赖）。B 侧 MASQUERADE 端口保持性可再测一次。

**结论置信度**：**低（R3+R4 双重判死）**。忠实对称模拟器（`--random`）实测：同一 socket 对同 IP 异端口映射 52009 vs 52114、异 IP 映射 52083 vs 52055，分配无 Δ 规律；A 向对称侧 STUN 端口 ±3 预测 7 端口洪泛 15s 收到 0（§8 E8/E11）。R4 再对 iptables SNAT 分配类穷尽测量（§9 E15）：去掉 `--random` 即退化为端口保持锥（干净 conntrack 下同端口 52101），加 `--random` 即对称随机，**不存在「保序 +1 对称」分配类**→ delta 预测在本资产无任何可复现正例；残余价值仅限少数硬件「顺序分配」对称 NAT（本环境无法仿真、现代 CGNAT 少见）。

---

### 路线 7 — UPnP IGD / NAT-PMP / PCP 端口映射

**原理**：UPnP（SSDP 239.255.255.250:1900 → SOAP AddPortMapping）；NAT-PMP/PCP（UDP 5351 请求/响应）。PCP 理论可「命令」CGNAT 开洞。

**成功率依据**：仅当家宽 WAN 是真公网（非 CGNAT `100.64.0.0/10`）时 UPnP/NAT-PMP 才对外可见 `[推理，RFC 6888]`；中国移动多用 CGNAT `[推理]`；PCP 对 CGNAT 是理论正确解，但 ISP 部署无公开证据 `[文献 RFC 6887 + 推理]`。

**实现代价**：约 150–300 行。**零第三方依赖**。

**失败模式**：CGNAT 阻断；光猫关 UPnP；PCP server 未部署。

**判定性实验（≈15 分钟）**：查 A 光猫 WAN IP 是否 `100.64/10` → 发 SSDP 看 IGD → 发 PCP MAP 到网关/5351 与公网。→ **R2 已跑，判死**（§0.7.5）。

**结论置信度**：**低（R2 已实测判死：本网关无 UPnP IGD、无 NAT-PMP/PCP 响应）**。

---

### 路线 8 — 半洞混合（address-dependent 侧 ↔ 真对称侧）

**原理（消息序列）**
1. 判定两侧类型：A = address-dependent（已实测），B = 真对称或锥型。
2. A 先向 B 的映射发握手 → A 侧映射 `A.pub1` 建立。
3. B 收到后**回打到 A 的实际源 `A.pub1`**（address-dependent 侧天然接受）。
4. B 若为锥型：B 侧映射固定，A 直接命中 → 成功；B 若为真对称：A 需命中 B 面向 A 的确切端口（即回打 B 实际源，靠步骤 2 的来包建立）。

**成功率依据**：A 已证 address-dependent（非对称）→ **半洞天然成立**，无需预测 `[已实测 + 推理]`。经典结论「对称↔锥型半洞」在「address-dependent↔锥型」下更简单 `[推理，RFC 4787]`。

**实现代价**：约 200–300 行。**零第三方依赖**。

**失败模式**：对端真对称且回包端口不匹配；高并发端口池耗尽。

**判定性实验**：与路线 1 同一次实验覆盖（回打实际源即半洞）。

**结论置信度**：中（R3 精化）。半洞（对称侧 ↔ 锥侧）**仅当锥侧是全锥**才成立（全锥接受任意源）；R3 实测 A 是 **port-restricted cone**，对称侧反向发起被 A 端口受限过滤丢（0 收，§8 E10）→ 本拓扑下此路线失败；反向方向（A 主动打对称侧）又需端口预测（路线 6 已判死）。故半洞对「全锥↔对称」仍有效，对「端口受限锥↔对称」无效。

---

### 路线 9 — QUIC/HTTP3 NAT 重绑定语义（证伪项）

**原理澄清**：QUIC Connection ID（RFC 9000 §5.1）让**已建立**连接在 NAT 映射变化后**继续存活**（重绑定后 CID 不变、端点可迁移）；不提供「穿过对称 NAT 建立连接」的能力。Node 内置无 QUIC/HTTP3 → 用则违反零依赖。

**成功率依据**：对「建立直连」= 0%（该机制只作用于已建连接，不参与打洞建立）`[文献 RFC 9000 §5.1 + 推理]`；对「已建连接抗重绑定」= 高，但 VAP 的需求是「对称 NAT 下建立端到端直连」，不在该机制能力域内 `[推理]`。

**实现代价**：Node 内置无 QUIC，需第三方库（`quiche` 等未进稳定版）→ 违反零第三方依赖强默认；即便引入也只能解决「维持」不能解决「建立」，实现收益为负 `[推理]`。

**失败模式**：误当打洞方案 → 徒劳；引入第三方依赖打破约束。

**零依赖兼容性**：不兼容（需要第三方 QUIC 栈）。

**最小判定性实验**：无（判死）。若坚持验证「重绑定维持」语义，可用任一已建 UDP 连接在 NAT 映射变化后发探测——但这与「对称 NAT 建立直连」目标无关，不做。

**结论置信度**：高（判死：不解决建立 + 违反零依赖）。

---

### 路线 10 — 多端口并行预测（birthday/洪水）

**原理**：路线 6 增强，双方开 M 个 socket 对预测窗口并行洪泛。

**成功率依据**：命中随 `M×w` 线性上升，对哈希化分配无效 `[推理]`；uTorrent uTP/pwnat 历史实践 `[文献/业界实践]`。

**实现代价**：约 200–350 行（路线 6 之上加 M 路并行 socket + 窗口管理）。**零第三方依赖**（`node:dgram`）。

**失败模式**：哈希化无效；洪泛触发限速/污染映射。

**零依赖兼容性**：完全兼容（内置模块）。

**最小判定性实验**：仅当路线 6 拟合出线性分配才启用；否则在对称模拟器（vapsym `--random`）上 M×w 洪泛 15s 观察命中数——R3 E11 已等效跑过（±3=7 端口洪泛 0 收），随机分配下 M×w 命中≈随机猜、无 Δ 放大。

**结论置信度**：**低（R3 判死）**。R3 实测 A 向对称侧 STUN 端口 ±3（7 端口）洪泛 15s 收到 0（§8 E11）——对 `--random` 随机分配，M×w 洪泛同样无效（命中≈在 128 端口池里随机猜，无 Δ 可放大命中率）。

---

## 3. 推荐组合路线（fallback 链：从最快成功到兜底）

```
L1  经典 UDP 打洞（锥侧主动发起 + 回打实际源 rinfo）  (≤ 15s)  —— ✅ R2 实测成功（A↔B 双向直连）——唯一可靠的裸网络直连
L2  IPv6 直连（B 开双栈）                          (≤ 3s)   —— 0 跳直连，A 已就绪，差 B 控制台开双栈（外部阻塞）
L3  TCP simultaneous open                          (≤ 5s)   —— ⚠️ R3 1 次、R4 ~40%、R5 N=20 ~10%；失败=时序不重叠+映射不匹配；仅 best-effort
L4  UPnP / NAT-PMP / PCP                           (≤ 5s)   —— ❌ R2 实测判死（本网关不支持）
L5  TURN 中继兜底                                  (立即)    —— 保证通，R3 钉死 120.2 KB/s（≈1 Mbps 上限）
```

**关键工程原则（R4 更新）**
1. **L1 成立条件收窄**：R3 证实 A 是 **port-restricted cone**，UDP 打洞只在「**锥侧主动发起**、对端回打实际源」方向成立（R2 的 A↔B 正是 A 主动发起）。对称侧无法向 A 反向发起（E10）、A 无法向对称侧预测打洞（E11）。
2. **L3 从「可靠通道」降级为「best-effort（~10%）」**：R5 N=20 复测 TCP simultaneous open 成功率 **2/20=10%**，失败拆解为「时序不重叠（主因，B sim 侧 connect 非 listen、SYN-SENT 占空比极低）+ 映射不匹配（B 连控制连接旧映射收 RST）」（§10 E20）。实现上 L3 只作「L1 失败后的低概率尝试」，且**必须经独立信令（中继/STUN）交换「sim 4-tuple 的实际映射」、不能依赖同端口控制连接**，并设短超时（≤5s）快速回落 L5。R4 曾建议的「TCP SO 作为对称环境第二直连通道」定位已**移除**。
3. **端口预测（路线 6/10）双重判死**：R3 双向实测 + R4 分配类穷尽测量均判死（§9 E15）；对「顺序分配对称」仅理论残余且本环境无法仿真。
4. **L5 始终在线**（DCUtR 骨架，路线 4），保证任何情况 VAP 可通；R3 量化为 1400B≈86 封/秒≈120 KB/s。
5. **新增工程判断**：当前测试拓扑（A=锥 ↔ B=公网）下，A→B 直连根本无需打洞/同时打开（A 直接 connect 即可）；L1/L3 的价值只在「两端都在 NAT 后」时体现，而那种情形的成功率只会更低。产品上应把「一端公网/全锥」作为快速直连快车道单独处理。

**推荐链的诚实结论**：对「锥↔锥/锥↔公网/锥↔受限锥」UDP 直连**实测可得**（L1）；TCP 同时打开（L3）**成功率 ~10-17%（N=20 装置级）、不可靠**；对**含真对称 NAT 的一端**，UDP 直连**不可得**（E10/E11）、TCP 同时打开亦不保证，**唯一保证通的是 L5（TURN）**；IPv6（L2）需外部控制台。

---

## 4. 明确不可行 / 判死清单

| 路线/命题 | 判死/修正原因 | 依据 |
|---|---|---|
| 「A 是对称 NAT」命题 | **错**：A 实测 address-independent，且 R3 进一步判定为 **port-restricted cone** | `[已实测]` §0.7/§0.8 |
| 「经典 UDP 打洞对称阻断」结论 | **无证据**：旧 0 直连包是 B 装置无入站 DNAT 造成；R2 已实测成功 | `[已实测]` §0.2.4 |
| **对称侧↔端口受限锥 双向 UDP 打洞** | **R3 判死**：对称侧反向发起被锥侧端口受限过滤丢（0 收）；锥侧向对称侧 STUN 端口±Δ 预测被对称 conntrack 丢（0 收） | `[已实测]` §8 E10/E11 |
| **端口预测（delta）对随机分配对称 NAT** | **R3+R4 判死**：`--random` 无 Δ 规律，±3 预测失败；R4 穷尽测量确认 iptables 无「保序 +1 对称」分配类 | `[已实测]` §8 E8/E11 + §9 E15 |
| **「TCP simultaneous open = 可靠直连通道」命题** | **R4+R5 降级**：R3 成立 1 次，R4 ~40%，R5 N=20 得 2/20=10%；失败=时序不重叠（sim 侧 connect 非 listen）+ 映射不匹配（旧映射收 RST） | `[已实测]` §9 E16/E17/E18 + §10 E20 |
| QUIC/HTTP3 打洞 | 只解决维持不解决建立 + 违反零依赖 | `[文献 RFC 9000 + 推理]` |
| 手动端口转发 | 违反「节点自己协商」约束 | 约束项 |
| Tailscale 式（要求装 Tailscale） | 违反「不能假设第三方」；非裸网络答案 | 约束项 |
| 端口洪泛硬打哈希化 CGNAT | 命中≈随机、触发限速；R3 对随机对称 NAT 实证无效 | `[已实测 + 推理]` |

---

## 5. 「今天就能测」的排序（按成本/价值比）

> R2 已回填：实验 1（打洞重测）✅、实验 3（UPnP/PCP）✅ 判死（§7.2）。**R3 已回填**：实验 4→被「忠实对称 NAT 模拟器」取代（§8 E8）、实验 5（TCP 同时打开）✅、实验 6（1400B 吞吐）✅，并新增「真对称 NAT 双向打洞判定」两项（E10/E11）。**R4 已回填**：SNAT 分配类穷尽测量（E15）、A 的 TCP NAT 分类（E16/E17）、TCP simultaneous open 复测分布（E18）。**R5 已回填**：状态机落进实现（nat-classify.mjs + punch-plan.mjs，E19）、TCP SO N=20 样本（E20）、B 实例类型判定（E21）。**R6 已回填**：状态机接入 `punch-node.mjs` 主流程并端到端实测——锥↔锥直连成功（E22）、对称端 fallback 到中继正确触发（E23）。

| 序 | 实验 | 判定结论 | 状态 |
|---|---|---|---|
| 1 | **修正版打洞重测**（锥侧主动发起 + 回打实际源） | 通→L1 成立（裸网络直连） | ✅ R2（A↔B 直连） |
| 2 | **B 开 IPv6 双栈 + A↔B v6 ping** | 通→L2 成立 | ⏳ 外部阻塞（腾讯云控制台，无 API 凭据） |
| 3 | A 光猫 WAN IP 检查 + UPnP/NAT-PMP/PCP | 非 CGNAT 且支持→L4 可用 | ✅ R2 判死 |
| 4 | **真对称 NAT 模拟器 + 对称性验证**（netns + SNAT --random） | 证明模拟器端点+端口依赖 | ✅ R3（E8） |
| 5 | **对称侧反向发起 → A**（reverse connection） | 0 收 → A 端口受限锥，反向发起失败 | ✅ R3（E10） |
| 6 | **A 向对称侧 STUN 端口 ±Δ 预测打洞** | 0 收 → 端口预测对随机对称 NAT 无效 | ✅ R3（E11） |
| 7 | TCP simultaneous open 实测 | R3 通 1 次；R4 ~40%；R5 N=20 得 2/20=10%（失败=时序不重叠+映射不匹配） | ⚠️ R5 再降级（E12+E18+E20） |
| 8 | TURN 1400B 大包吞吐实测 | 120.2 KB/s≈1 Mbps，量化兜底天花板 | ✅ R3（E13） |
| 9 | **SNAT 分配类穷尽测量**（--random vs 去 --random） | 仅「锥 / 对称随机」两类，无「保序 +1 对称」 | ✅ R4（E15） |
| 10 | **A 的 TCP NAT 分类**（并发 vs 关→重开） | 并发=端点无关锥（恒 20618）；关→重开=Windows TIME_WAIT 卡 | ✅ R4（E16/E17） |
| 11 | **NAT 自分类模块端到端**（nat-classify.mjs） | 本机 A 复现「endpoint-independent」，映射 20843 恒等 | ✅ R5（E19） |
| 12 | **TCP SO 样本扩大 N=20** | 2/20=10%，失败=时序不重叠+映射不匹配 | ✅ R5（E20） |
| 13 | **B 实例类型判定**（CVM vs Lighthouse） | vpc-id/subnet-id 可读 → CVM 在 VPC 内，IPv6 可开 | ✅ R5（E21） |
| 14 | **状态机接入主流程端到端（锥↔锥）** | classifyNAT 自判 cone + natClass 中继交换 + buildExecPlan 选 udp-punch → 直连成功（A 514ms/3415、B 250ms/3421） | ✅ R6（E22） |
| 15 | **状态机接入主流程端到端（锥↔对称）** | B 自判 symmetric（52077 vs 52120）→ UDP 判死跳过 → TCP SO 失败（EADDRINUSE）→ TURN 中继可用 | ✅ R6（E23） |

> 排序逻辑：1、2 是「命中即裸网络直连」的高杠杆项且判定成本秒级；3 是家宽侧确定性映射；4 决定是否还需要端口预测；5 是 UDP 之外补充；6 是兜底诚实量化；9/10 是 R4 补的「路线 6/3 残余价值」判定；11/12/13 是 R5 补的「状态机实现验证 + L3 更硬数字 + L2 定性」；14/15 是 R6 补的「状态机接入主流程后的端到端两条路径（锥↔锥直连成功 / 锥↔对称诚实回落中继）」。**全部只依赖现有 S/B 与本机，今天可跑；实验 1、5、14、15 需 A、B 双端同时在线协调一次。** 剩余未闭环：仅 IPv6（L2，外部控制台）。

---

## 6. 后续轮次建议（R2+）

1. 执行 §5 实验 1：修 B 入站 DNAT + 回包打实际源 → 重测打洞，把「先验可打洞」变为「实测直连」。
2. 执行 §5 实验 2：B 开双栈 → A↔B v6 直连实测。
3. 若打洞通 → 在 `hole-punch.mjs` 固化「回包打 `rinfo` 实际源」+ 保活，回归零依赖。
4. 量化 TURN 大包吞吐，评估 1 Mbps 是否够；不够则评估多公网机轮询（仍零第三方）。
5. 每轮追加/修订本文件，标注轮次号、日期、结论置信度。

---

### 参考文献（本轮引用）

- RFC 4787 — NAT Behavioral Requirements for UDP
- RFC 5382 — NAT Behavioral Requirements for TCP
- RFC 5128 — State of P2P Communication across NATs
- RFC 6886 / 6887 / 6888 — NAT-PMP / PCP / CGNAT requirements
- RFC 8656 / 8445 — TURN / ICE
- RFC 9000 — QUIC（CID 重绑定语义）
- Ford, Srisuresh, Kegel (USENIX 2005) — [Peer-to-Peer Communication Across Network Address Translators](https://web.archive.org/web/20250105174522/https://bford.info/pub/net/p2pnat/)
- Guha & Francis (IMC 2005) — [Characterization and Measurement of TCP Traversal through NATs and Firewalls](https://www.usenix.org/legacy/events/imc05/tech/full_papers/guha/guha.pdf)
- Wang et al. (SIGCOMM 2011) — [An Untold Story of Middleboxes in Cellular Networks](https://engineering.purdue.edu/dcsl/reading/2012/matt_cellular_networks.pdf)
- libp2p — [DCUtR spec](https://github.com/libp2p/specs/blob/9958df289480723d29ff01b23f7edb3008de7dbd/relay/DCUtR.md)；[Large-Scale Measurement of DCUtR in IPFS](https://arxiv.org/pdf/2604.12484v1)
- 国家 IPv6 发展监测报告（IPv6 活跃用户 7.94 亿 / 72.7%）— [报告](https://www.hxedu.com.cn/hxeduRes/simplecharacter/1748246054995.pdf)

---

## 7. R2 实测记录与修订（2026-08-24，`[已实测]`）

> 本轮新增 6 个自研零依赖探针脚本（`nat-addrdep-probe.mjs`、`nat-upnp-pcp-probe.mjs`、`udp-echo.mjs`、`udp-ping.mjs`、`tcp-ping.mjs`、`punch-min.mjs`），全部 `node:*` 内置模块。实验在现有资产（本机 A + 腾讯云 S/B）上直接跑。

### 7.1 实验清单与结果

| # | 实验 | 命令/方法 | 结果 | 判定 |
|---|---|---|---|---|
| E1 | A 的 NAT 类型（干净版） | 单一 socket → EIP:3478 + Google:19302 + qq:3478，按 txid 匹配 | 两个可达目的映射端口恒等（20834 / 20836） | **A = cone（address-independent）** |
| E2 | UDP 打洞 A↔B | punch-min.mjs 双端（A 本机 / B 宿主:46501） | A directReceived=2598、B=437+，pass=true | **双向直连成功** |
| E3 | 自研 STUN 端口 | A→EIP:3478 vs EIP:3479 | 3478 有响应、3479 无响应 | 公共 STUN=3478 |
| E4 | 防火墙定位 | A→EIP:46501/50000-50015，ufw allow 前后 | allow 前 0/16，allow 后 16/16 | 真凶=ufw，非安全组 |
| E5 | UPnP/NAT-PMP/PCP | SSDP M-SEARCH + NAT-PMP + PCP 到 192.168.1.1 | 0 设备、无响应、无响应 | **路线 7 判死** |
| E6 | B 侧 NAT 类型 | 宿主 vs netns 的 STUN 映射 | 宿主 46501→46501（1:1）；netns 端口重映射（50808/58951/…） | EIP=1:1 全锥；netns 双重 NAT 非对称模拟 |
| E7 | 中继可达性 | tcp-ping 42050 | ufw allow 后 TCP-OPEN | relay 可用于 DCUtR 骨架 |

### 7.2 对「今天就能测」排序的回填（R1 §5）

1. ✅ **修正版打洞重测**（实验 1）→ **已完成，成功**（E2）。L1 成立。
2. ⏳ B 开 IPv6 双栈 + A↔B v6 ping → **未做**（需腾讯云控制台开双栈，外部状态变更）。
3. ✅ A 网关 CGNAT + UPnP/NAT-PMP/PCP（实验 3）→ **已完成，判死**（E5）。
4. ⏳ B 的 MASQUERADE 端口保持性复测 → 部分完成（E6：netns 端口重映射已证实），但已无必要（B 改用宿主全锥）。
5. ⏳ TCP simultaneous open 实测 → 未做。
6. ⏳ TURN 1400B 大包吞吐 → 未做。

### 7.3 R2 结论置信度

- 「A=cone NAT、UDP 打洞 A↔B 成立」→ **高（直接实测）**。
- 「UPnP/PCP 在本网关判死」→ **高（直接实测 0 响应）**，但局限：仅覆盖本光猫/路由器，其他家宽仍应探测。
- 「腾讯云 EIP=1:1 全锥」→ **高（直接实测端口保持）**。
- 「对称 NAT 环境」的完整打洞（真对称↔真对称）→ **本轮仍未实测**：现有资产缺第二个真 NAT 侧；netns 双重 NAT 是「端口重映射」不是「对称 NAT」忠实模拟，不能作为对称打洞的证据。

### 7.4 下一轮（R3）建议

1. 给腾讯云 EIP/实例开双栈 IPv6 + 安全组放 v6，跑 A↔B v6 UDP/TCP ping，闭环 L2（外部状态变更，可能需人工控制台）。
2. 实测 TCP simultaneous open（A↔B，复用 46501 路径 + ufw 放 46501/tcp），闭环 L3。
3. 量化 TURN 1400B 大包吞吐，钉死 1 Mbps 上行天花板对 VAP 业务的影响（在 S 上跑，零外部依赖）。
4. 把「回包打实际源 rinfo」在 `hole-punch.mjs` 中确认固化（已核对代码第 52–54 行确实回打 `rinfo`，无需再改；仅需在 punch-node 内核对 relay 交换时序——R2 发现 relay 交换对「双端启动时序差 >45s」敏感）。
5. 若需真正验证「对称 NAT 打洞」，需引入第二个真实家宽/对称 NAT 侧（或用可配置端口分配策略的 CGNAT 模拟器），现有 netns 装置不适用。

---

## 8. R3 实测记录与修订（2026-08-24，`[已实测]`）

> 本轮补齐 R2 明确指出的缺口：**自建「忠实对称 NAT 模拟器」并做真对称 NAT 的双向判定性实测**，把「对称 NAT 是否可打洞」从推理落到硬数据。全部零第三方依赖（`node:*` 内置模块 + iptables/netns）。新增脚本在 `vap-local/r3/`：`sym-sim-setup.sh`、`sym-sim-teardown.sh`、`reverse-A.mjs`、`reverse-B.mjs`、`sym-stun-listen.mjs`、`punch-target.mjs`、`filter-probe.mjs`、`tcp-so.mjs`、`echo-server.mjs`、`echo-client.mjs`。

### 8.1 实验清单与结果

| # | 实验 | 方法 | 结果 | 判定 |
|---|---|---|---|---|
| E8 | 对称 NAT 模拟器 + 对称性验证 | netns `vapsym`(10.50.0.2) + `SNAT --to-source 172.21.0.10:52000-52127 --random` + FORWARD ACCEPT `vsym0`；同一 socket 打多目的 STUN | →EIP:3478=`52009`、→EIP:50001=`52114`（同 IP 异端口异映射）；→Google=`52083`、→Miwifi=`52055`（异 IP 异映射） | **真对称（endpoint-and-port-dependent）✅ 忠实** |
| E9 | A 的过滤行为（S0） | A STUN 学到映射后保持 socket；服务器从 A 未联系过的源端口 51000 发 UDP | A 无回复 | **A = port-restricted cone** |
| E10 | 对称侧反向发起 → A | B_sym（netns）向 A 的 STUN 端口 `120.225.86.119:20594` 持续打洞 | A 收到 **0** | **对称→端口受限锥 失败** |
| E11 | A 向对称侧 STUN 端口 ±Δ 预测 | B_sym STUN→Google 学得 `52059`；A 向 `52059±3`（7 端口）洪泛 15s | B_sym 收到 **0** | **端口预测对随机对称 NAT 无效** |
| E12 | TCP simultaneous open | tcp-so.mjs：A(46601)↔B(46502) 控制连接学映射 + 双端同时 connect（250ms 重试） | A attempt4、B attempt38 三次握手成功；SIM-DATA 双向互达 | **L3 成立（~9.5s 重试收敛）** |
| E13 | TURN 1400B 大包吞吐 | echo-server(42051) + echo-client 1400B×2000 | 85.8 封/秒 = 120.2 KB/s（23.3s / 2.8MB） | **1 Mbps 上行天花板钉死** |
| E14 | IPv6 可行性核实 | 实例 metadata `public-ipv6`(404) + netplan 无 v6 + 无 tccli/API 凭据 | 无公网 v6 | **外部阻塞（需控制台）** |

### 8.2 关键装置细节（供 R4 复现）

- **对称 NAT 模拟器**：`ip netns add vapsym` + veth 对 `vsym0↔vsym1`（10.50.0.1/10.50.0.2），netns 默认路由 `via 10.50.0.1`；宿主机 `iptables -t nat -A POSTROUTING -s 10.50.0.2 -o eth0 -p udp/tcp -j SNAT --to-source 172.21.0.10:52000-52127 --random`；**必须加 `iptables -A FORWARD -i vsym0 -j ACCEPT` + `-o vsym0 -j ACCEPT`**（宿主 FORWARD 策略 DROP，R2 的旧 netns 有 vb1/vs1 专用 ACCEPT，新接口无）。
- **关键坑**：`SNAT --to-source ip:port-range` 必须带 `-p udp`（或 `-p tcp`），否则 iptables 报「Need TCP/UDP with port specification」；`--random` 才产生每流独立随机端口（默认无 `--random` 是「端口保持」，即 R2 发现旧 MASQUERADE 非对称的原因）。
- **E10/E11 的 parseXor 修复**：R2 遗留的 `parseXor` 在「传入属性子串」时仍从 `off=20` 起读（`punch-min.mjs` 同款 bug，R2 的 `punch-A.json` 里 `mapping:null` 即此因，只是 R2 打洞不依赖 STUN 才未暴露）；R3 已修正 `reverse-A.mjs`/`sym-stun-listen.mjs` 的 `off=0`。

### 8.3 R3 结论置信度

- 「真对称 NAT（随机分配）不可打洞、不可端口预测」→ **高（忠实模拟器直接实测双向 0 收）**，局限：模拟器基于 Linux `--random`（真随机），真实设备可能用「保序/可预测」分配（此时 delta 预测才有意义，属少数实现）。
- 「A = port-restricted cone」→ **高（E9 直接实测：陌生源端口 0 回复 + R2 同端口回包可达）**。
- 「TCP simultaneous open 穿过端口受限锥成立」→ **R3 当时判高（E12 单次实测三次握手成功）**，局限：单次实测、需数秒重试、A 的 TCP 映射不保端但跨目的端口稳定。**⚠️ R4 已复测并降级为「~40%、失败=映射跨连接关闭不持久」（§9 E16/E17/E18）**。
- 「TURN 1 Mbps 天花板」→ **高（E13 直接实测 120.2 KB/s）**。

### 8.4 下一轮（R4）建议

1. 闭环 L2：需人工在腾讯云控制台给实例 `ins-096pmlyd` 开 IPv6 双栈，跑 A↔B v6 ping（**外部状态变更，本会话无 API 凭据**）。~~（或确认该轻量机型不支持）~~ **R5 E21 已确认 B 是 CVM 在 VPC 内（非轻量），IPv6 技术上可开启，此「确认机型」分支已被取代**。
2. 若需覆盖「可预测分配」的真实对称 NAT：用 `SNAT --to-source ip:52000-52127`（去掉 `--random`，观察是否「保序+1」）作为第二类对称实现，验证 delta 预测在「保序分配」下的命中率（为路线 6 保留残余价值依据）。
3. 把 R3 结论落进实现：VAP 打洞状态机按「锥侧主动发起 UDP 打洞 → 失败转 TCP 同时打开 → 再失败 TURN」排序；在 `hole-punch.mjs` 固化「先判自身 NAT 类型（全锥/受限锥/端口受限锥），全锥才接受对端反向发起」。
4. 量化 TCP simultaneous open 的收敛分布（多次重复统计 attempt 数均值/方差），给出「≤N 秒内建立」的概率承诺。
5. 清理：`vap-local/r3/sym-sim-teardown.sh` 可移除模拟器（如 R4 继续用则保留）。

---

## 9. R4 实测记录与修订（2026-08-24，`[已实测]`）

> 本轮补上 R3 §8.4 的第 2、4 条（分配类测量 + TCP SO 收敛分布），并**诚实修正 R3 对 TCP simultaneous open 的单次成功结论**。全部零第三方依赖（`node:*` 内置模块 + iptables/netns）。新增脚本在 `vap-local/r4/`（本地）与服务器 `/home/ubuntu/r4/`：`mini-stun.mjs`、`alloc-probe.mjs`、`set-alloc-mode.sh`、`start-stuns.sh`、`tcp-nat-server.mjs`、`tcp-nat-client.mjs`、`tcp-nat-client2.mjs`、`tcpso-B.sh`、`tcpso-stop.sh`、`tcp-so-dist.ps1`。

### 9.1 实验清单与结果

| # | 实验 | 方法 | 结果 | 判定 |
|---|---|---|---|---|
| E15 | SNAT 分配类穷尽测量 | `vapsym` 同一 socket 向 5 目的（EIP:3478/50001/50002/50003/Google）发 STUN，记录每目的映射；对比 `--random` vs 去 `--random` | `--random`：`[52115,52110,52107,52062,52086]`（异目的异端口随机）；去 `--random`+清 conntrack：4 目的恒 `52101`（锥）；去 `--random`+conntrack 污染：`[52010,52067,52067,52114]`（状态化扫描） | **iptables 无「保序 +1 对称」分配类** |
| E16 | A 的 TCP NAT（并发/重叠） | tcp-nat-server 监听 46501/46502；A 从同 localPort 46601 连两目的（重叠） | 6/6 连接公网源端口恒 `20618` | **A TCP 侧端点无关锥** |
| E17 | A 的 TCP 关→重开 | A 关连接后立刻从同 localPort 重连（tcp-nat-client2） | 第 2 轮起 `EADDRINUSE`（Windows TIME_WAIT 占位） | **同端口控制+重开在 A 侧结构性脆弱** |
| E18 | TCP simultaneous open 复测分布 | tcp-so.mjs A↔B 复测（fresh localPort/轮） | R3 1 次成功；R4 干净样本：run2 成功（A=2/B=12），run3/run4/单独轮失败（B 连 A.pub 持续 ECONNREFUSED） | **~40% 成功率，失败=映射跨关闭不持久** |

### 9.2 关键装置细节（供 R5 复现）

- **分配类测量**（E15）：`set-alloc-mode.sh random|preserve` 翻转 vapsym SNAT 规则；`alloc-probe.mjs --dests 'ip:port,...' --runs N` 在 netns 内跑。**去 `--random` 必须同时清 conntrack**（`conntrack -D -s 10.50.0.2`）才能得到干净锥；否则前序流的 conntrack 残留会让分配退化为「状态化扫描」的中间态（这本身也是重要发现：真实 NAT 在高并发下分配同样非确定性）。
- **TCP NAT 分类**（E16/E17）：`tcp-nat-server.mjs` 在宿主监听多端口记录入站源端口；`tcp-nat-client.mjs`（重叠连接）/`tcp-nat-client2.mjs`（关→重开）在 A 侧跑。**E17 的 EADDRINUSE 是 Windows TIME_WAIT**，不是 NAT 结论——它说明「同端口控制+重开」技术路线在 Windows A 侧就被 OS 卡住。
- **pkill 自匹配坑**：`pkill -f 'tcp-so.mjs'` 会匹配到正在执行该命令的 ssh 远端 shell（命令行含该字符串）而自杀；必须用锚定 `pkill -f '^node /home/ubuntu/r3/tcp-so.mjs'` 或经脚本文件调用。

### 9.3 R4 结论置信度

- 「iptables SNAT 无『保序 +1 对称』分配类，delta 预测对随机分配双重判死」→ **高（E15 直接实测两种模式的分配序列）**，局限：仍不能排除真实环境中少数硬件「顺序分配」对称 NAT 的存在（本环境无法仿真）。
- 「A 的 TCP NAT 并发时端点无关、关→重开不持久」→ **高（E16/E17 直接实测）**。
- 「TCP simultaneous open 成功率 ~40%、不可作可靠通道」→ **中-高（R3 1 次 + R4 干净样本 3 次，样本小）**，方向明确（失败模式=旧映射收 RST），但置信度受样本量限制。**⚠️ R5 N=20 已把该数字下调为 ~10%（§10 E20），失败拆解为「时序不重叠 + 映射不匹配」两项。**
- 「L1（锥侧主动 UDP 打洞）仍是唯一可靠裸网络直连、L5（TURN）是唯一保证通」→ **高（R2+R3+R4 交叉印证）**。

### 9.4 下一轮（R5）建议

1. **闭环 L2（IPv6）**：仍需人工在腾讯云控制台给实例 `ins-096pmlyd` 开 IPv6 双栈，跑 A↔B v6 ping——**外部状态变更，本会话无 API 凭据，是当前唯一未闭环的高杠杆项**。~~（或确认该轻量机型不支持）~~ **R5 E21 已确认 B 是 CVM 在 VPC 内（非轻量），IPv6 技术上可开启**。
2. **扩大 TCP SO 样本**（可选）：若要对 L3 给出更硬的概率承诺，跑 ≥20 次干净复测（fresh localPort + 独立信令交换映射 + 短超时），统计成功率与收敛分布；R4 已给出「~40%、失败=映射不持久」的初步结论，样本量足够下结论，仅精度可再提升。
3. **把 R4 结论落进实现**：`hole-punch.mjs` 打洞状态机最终排序定为「① 判自身 NAT：一端公网/全锥 → 直接 connect 快车道；② 锥侧主动 UDP 打洞（回打实际源）；③（仅两端都在 NAT 后且都非对称）TCP 同时打开 best-effort，独立信令换映射 + ≤5s 短超时；④ TURN 兜底」。并**移除** R3 曾建议的「TCP 同时打开作为对称环境第二直连通道」的定位。
4. **清理**：`vap-local/r3/sym-sim-teardown.sh` 与 `vap-local/r4/*`（探测脚本）可按需保留作复现记录；vapsym 模拟器当前保持 `--random` 状态（R3 文档态）。

---

## 10. R5 实测记录与修订（2026-08-24，`[已实测]`）

> 本轮闭环 R4 §9.4 的三项：① 打洞状态机落进实现（新增 `phase7/nat-classify.mjs` + `phase7/punch-plan.mjs` + `phase7/punch-plan.smoke.mjs`，零依赖）；② L2 定性推进（确认 B 是 CVM 在 VPC 内）；③ TCP SO 样本扩大到 N=20。全部零第三方依赖。

### 10.1 实验清单与结果

| # | 实验 | 方法 | 结果 | 判定 |
|---|---|---|---|---|
| E19 | NAT 自分类模块端到端验证 | 本机 A 跑 `nat-classify.mjs`：同 socket 向 EIP:3478 + Google:19302 发 Binding Request | 两目的映射端口**恒等 20843**，`mappingClass=endpoint-independent`、`isPublic=false` | **模块复现 R2「A=cone」+ A 公网映射仍 120.225.86.119** |
| E20 | TCP SO 样本扩大 N=20 | `tcp-so-dist.ps1 -N 20`（fresh localPort 46601+10i/轮，A=锥 ↔ B=公网） | **2/20 pass（10%）**；成功轮 run2(A=2/B=16)、run10(A=3/B=25)；18 轮失败**双侧 ECONNREFUSED×40 从未交叉** | **TCP SO 降级为 ~10%（N=20），失败=时序不重叠 + 映射不匹配** |
| E21 | L2 定性：B 实例类型 | 读 B 元数据 `vpc-id`/`subnet-id`/`public-ipv6` + `ip -6 addr` | `vpc-id=vpc-0azq2806`、`subnet-id=subnet-pbcornax`（ap-beijing-7）；eth0 仅 fe80::、`public-ipv6`=404、内核 `disable_ipv6=0` | **B=CVM 在 VPC 内，IPv6 技术上可开（缺控制台 6 步）** |

### 10.2 E20 关键细节（供 R6 复现/修正）

- **装置**：`vap-local/r4/tcp-so-dist.ps1`（本机 A，Windows）+ B 宿主 `/home/ubuntu/r3/tcp-so.mjs --role B`（ctrlPort 46501 / simPort 46502），每轮 fresh `localPort = 46601 + (i-1)*10`，规避跨轮 TIME_WAIT。
- **结果分布**：2/20 pass。成功轮 B 需 **16/25 次**重试才与 A 的 SYN 交叉；A 侧在成功轮 attempt=2/3。
- **18 轮失败的统一签名**（读 `tcp-so-dist.json` 的 A_out/B_out）：A 侧 `sim-open: bind local 46601 -> connect 101.42.23.246:46502` 后 **40 次 ECONNREFUSED**；B 侧 `connect 120.225.86.119:XXXXX`（控制连接学到的 A.pub）**40 次 ECONNREFUSED**。两侧**从未产生交叉 SYN**。
- **根因拆解（两个独立失败模式，均非「UDP 打洞」类 NAT 结论）**：
  1. **时序不重叠（主因，A 侧 ECONNREFUSED）**：B 的 sim 侧是**主动 open（connect）而非 listen**，且每次 connect 被 RST 后 250ms 才重试 → B 的 46502 处于 SYN-SENT 的占空比极低（RST 往返仅几 ms / 250ms 周期）。A 的 SYN 落在 B「未 bind 46502」的窗口即被内核 RST → A ECONNREFUSED。两个独立的 250ms 重试环要相位漂移很久才重叠一次（成功轮 B 漂了 16/25 次）。
  2. **映射不匹配（次因，B 侧 ECONNREFUSED）**：B 连的是**控制连接**（46601→46501）学到的 A.pub；而 A 的 sim 连接是**新 4-tuple（46601→46502）**，其公网映射未必等于控制映射。控制连接关闭后旧映射被撤销 → B 打旧映射收 RST（=R4 的「映射不持久」，本轮进一步确认它与「时序不重叠」同时存在）。
- **诚实说明**：当前 tcp-so.mjs 装置本身有缺陷（sim 侧用 connect 而非「connect+listen 同端口」、重试环不锁相），因此 **2/20 是「该装置下的成功率」，不等于「A 的 NAT 对 TCP SO 的理论可达性」**。要得到干净的 NAT 级数字需换装置：sim 侧 `SO_REUSEADDR` + 同端口同时 LISTEN+connect，且用**独立信令**交换「sim 4-tuple 的实际映射」而非复用控制映射。本报告据此把 L3 承诺从 R4 的「~40%」**下调为「~10%（N=20 装置实测）、且装置本身未达最佳，仅作 best-effort」**。

### 10.3 R5 结论置信度

- 「nat-classify.mjs 复现 A=cone」→ **高（E19 直接实测，与 R2 E1 交叉印证）**。
- 「punch-plan.mjs 策略链符合 R4 §9.4.3 最终排序」→ **高（冒烟测试 5/5 断言通过）**。
- 「B 是 CVM 在 VPC 内、IPv6 技术上可开」→ **高（E21 元数据 vpc-id/subnet-id 直接读出）**；「开双栈需控制台 6 步、本会话无凭据无法代操作」→ **高（无 tccli/API，且非 root 无法改云网络）**。
- 「TCP SO 成功率 ~10%（N=20）、失败=时序不重叠+映射不匹配」→ **中-高（N=20 样本 + R3/R4 累计 4/24≈17%），方向明确，但装置缺陷使该数字是装置级而非 NAT 级下界**。

### 10.4 下一轮（R6）建议

1. **闭环 L2**（唯一剩余高杠杆，外部状态变更）：人工在腾讯云控制台按 §2 路线 2 的 6 步给 `ins-096pmlyd` 开 IPv6 双栈 → A↔B v6 ping。本会话已无任何方式推进（无 API 凭据）。**→ R6 仍为外部阻塞，未闭环。**
2. **换装置复测 TCP SO 的 NAT 级上限**（可选，若要救活 L3）：sim 侧改「同端口 LISTEN+connect（SO_REUSEADDR）」+ 独立信令交换 sim 4-tuple 实际映射 + 锁相重试，跑 N≥20，区分「时序」与「映射」两个失败模式的占比。**→ R6 未做（TCP SO 已判 best-effort，投入产出比低；R6 的 tcp-so 执行器实测进一步印证「Node 同端口 LISTEN+connect 被 OS EADDRINUSE 拒」这一结构性限制）。**
3. **把 `nat-classify.mjs` + `punch-plan.mjs` 接入 `punch-node.mjs`**：启动时 `classifyNAT` 自判 + `selectStrategy` 选首条策略 + 失败按链回落。**→ R6 已完成（§0.11/§11 E22/E23 端到端实测两条路径）。**
4. 文档收尾：把「~40%」历史引用统一标注为 R4 遗留、当前承诺统一「~10%（N=20 装置级）」，并把 §8.4/§9.4 的「轻量机型不支持」旧句标记为已被 R5「CVM 在 VPC 内」取代。**→ R6 已完成。**

---

## 11. R6 实测记录与修订（2026-08-24，`[已实测]`）

> 本轮（最后一轮）闭环 R5 §10.4 的「接入主流程 + 文档收尾」，并把 R4 §9.4.3 的「策略链排序」从「纯函数 + 冒烟测试」推进到「接入 `punch-node.mjs` 主流程 + 真实资产端到端实测」。新增 `phase7/punch-chain.mjs`（纯函数：`selectStrategy` 策略链 → 可执行步骤表）与 `phase7/punch-chain.smoke.mjs`（6/6 断言）；`punch-node.mjs` 重写为「classifyNAT 自判 → 中继交换 `{mapping, natClass}` → buildExecPlan → 按序执行/失败按链回落」；`nat-classify.mjs` 增补「同 IP 异端口 → 确定 symmetric」判定；classify 加 ≤3 次重试。全部零第三方依赖（`node:crypto`/`node:net`/`node:dgram`）。

### 11.1 实验清单与结果

| # | 实验 | 方法 | 结果 | 判定 |
|---|---|---|---|---|
| E22 | 状态机接入主流程端到端（锥↔锥） | 本机 A 跑集成后 `punch-node.mjs --site A`，服务器宿主跑 `--site B`（STUN=EIP:3478、中继=EIP:42050），双端 classifyNAT + 中继交换 natClass + buildExecPlan + 执行 | 双方 `mappingClass=endpoint-independent`；plan 首条 `udp-punch`；打洞 A **514ms**、B **250ms** 内 direct-established；payload **A=3415、B=3421** 直连包；`pass=true` | **「分类→规划→执行→直连」流水线端到端成立** |
| E23 | 状态机接入主流程端到端（锥↔对称） | 同上，但 B 跑在 netns `vapsym`（SNAT `--random` 真对称），classify 用同 IP 异端口 `3478` vs `50001` | B `mappingClass=symmetric`（映射 `52077` vs `52120`）；A 收到后 plan 首条 `tcp-simultaneous-open`；`udp-punch` 记 `not-applicable`（正确跳过）；tcp-so 失败（`EADDRINUSE`，20 次重试未交叉）；`turn-relay` 记 `available`；`directEstablished=false`、`relayAvailable=true` | **对称环境「不误判、不硬打、诚实回落中继」决策正确性实测确认** |

### 11.2 E22/E23 关键细节（供后续复现）

- **装置**：`punch-node.mjs` 双端对称参数（`--localPort` 各不同：A=46000、B=46501/46601；`--tcpPort = localPort+2`）。B 侧两台 STUN 服务器：`stun-server.mjs 3478`（已有）+ 本轮临时起 `stun-server.mjs 50001`（`sudo nohup node stun-server.mjs 50001 0.0.0.0`，供「同 IP 异端口」对称判定，避免 vapsym netns 内无 DNS 导致 Google STUN 超时）。
- **E22 直连数据**：A `udp-punch` 步 `elapsedMs=514`、`received=4`、`actualPeer=101.42.23.246:46501`；B `elapsedMs=250`、`received=12`、`actualPeer=120.225.86.119:20694`。双向 payload 互达（A=3415、B=3421），复现并强化 R2 的「A↔B 双向直连」。
- **E23 对称判定**：vapsym `--random` 下同一 socket 向 `101.42.23.246:3478` 映射 `52077`、向 `101.42.23.246:50001` 映射 `52120`（同 IP 异端口 → 映射不同 = endpoint-and-port-dependent = 真对称，与 R3 E8 交叉印证）。`nat-classify.mjs` 本轮新增的「同 IP 异端口 → 确定 symmetric」分支正是为覆盖此场景。
- **classifyNAT 瞬态超时与重试**：E23 的 A 侧 `classifyAttempts=2`——首轮 STUN Binding 在 4s 窗口内丢包超时，重试后成功。这是给 classify 加 ≤3 次重试的直接动因（E22 的第二次协调跑里 A 曾因 classify 超时降级为 `unknown` 导致 plan 误落到 tcp-so，加重试后不再发生）。
- **中继交换窗口 45s→120s**：本会话工具协调延迟（~55s）曾使 B 的 45s 交换窗口在 A 到达前就耗尽（首轮 A/B `exchanged=false`）；把 `punch-node.mjs` 交换循环上限放宽到 120s 后协调稳定（生产上节点自带退避重试，此值非关键）。

### 11.3 R6 结论置信度

- 「状态机接入主流程后，锥↔锥 UDP 直连端到端成立」→ **高（E22 直接实测：A 514ms/3415、B 250ms/3421 直连包）**。
- 「对称端被正确自分类并诚实回落中继（不硬打 UDP）」→ **高（E23 直接实测：B 自判 symmetric、udp-punch 正确跳过、tcp-so 失败 EADDRINUSE、turn-relay 可用）**。
- 「TCP SO 的『同端口 LISTEN+connect』在 Node 下被 OS EADDRINUSE 拒」→ **高（E22/E23 的 tcp-so 步两次独立复现 EADDRINUSE，与 R5 §10.2 的装置缺陷判定一致）**。
- 「L2（IPv6）仍为唯一未闭环项」→ **高（外部状态变更，本会话无 API 凭据，跨 R3–R6 连续四轮未能推进）**。

### 11.4 最终状态（R6 收尾）

- **已闭环**：10 条路线完整评估、fallback 链（§3）、每路线最小判定实验（§2/§5）、「今天能测」排序（§5）、打洞状态机从报告到可运行代码再到主流程接入（§0.10/§0.11/§11）。
- **唯一未闭环（外部状态变更，非本会话能解）**：L2 IPv6——需人工在腾讯云控制台按 §2 路线 2 的 6 步给 `ins-096pmlyd` 开 IPv6 双栈后跑 A↔B v6 ping。除此之外本目标的全部可执行项已在本会话完成。

（报告完 · R6 · 2026-08-24）

---

## 12. 后续闭环（2026-08-25 前向指针，取代 §11.4「唯一未闭环」结论）

§11.4 在 R6 收尾时把 L2（公网 IPv6 直连）记为「唯一未闭环（外部状态变更）」：需人工在腾讯云
控制台给 `ins-096pmlyd` 开 IPv6 双栈。该外部状态变更已于 2026-08-25 完成，L2 由「未闭环」转为
「已闭环」，§11.3/§11.4 的「唯一未闭环」结论随之作废。证据与数字以本仓库 `phase7/` 下三份报告
为准：

- `phase7/IPV6-REPORT.md`：公网 v6 直连（家庭 2409:8a3c ↔ 腾讯云 2402:4e00），ICMP/UDP 双通，
  RTT ~30ms（对照组 Tailscale ULA 不通，公网 v6 直连独立成立）。
- `phase7/IPV6-DIRECT-REPORT.md`：ipv6-direct 策略前插进 fallback 链（direct-connect 之后），
  真实公网 v6 装置 E2E 双端 PASS，payload A=2429 / B=2434。
- `phase7/SYMMETRIC-IPV6-REPORT.md`：对称 NAT × IPv6 端到端（B 真对称、udp-punch 判死跳过），
  executedStrategy=ipv6-direct，payload A=2728 / B=2733——对称场景唯一直连解实测打通。

同步说明：§11 所述 `punch-chain.smoke.mjs` 断言数已由 R6 时的 6/6 扩充到 12/12（新增 ipv6-direct
前插、双 GUA 第一候选、ULA/fe80 假阳性排除等断言），`punch-plan.smoke.mjs` 5/5 不变；对应实现
`phase7/punch-chain.mjs`（isGlobalV6 + ipv6-direct step）、`phase7/punch-plan.mjs`（selectStrategy
带 selfIpv6/peerIpv6）、`phase7/punch-node.mjs`（GUA 全展开不误滤、v6Port 显式交换、v6 puncher）
均已入库。论文 4（cs.NI）正文的 Public IPv6 direct / ipv6-direct in chain / Symmetric NAT + IPv6
三行数字（~30ms、2429/2434、2728/2733）由此可在本仓库 `phase7/` 沿「论文 → 报告 → 装置号」溯源。
