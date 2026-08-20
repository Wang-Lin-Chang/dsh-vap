# VAP v0 实测装置档案（E01-E03）

运行：`node experiments/vap-experiment.mjs`（真实文件系统，临时战场，跑完自清理）

## E01 异构节点互动

原生侦察兵 + 模拟框架节点 + 脑进程全链：领任务（O_EXCL 租约）→ 干活 → 完成（EXIT 记录）→ 两个节点各发 L2a 战报信封 → 脑进程裁决 2/2 入账。

**判决：通过。** 任务完成入 done、两封信封全部通过三闸入账。

## E02 伪造声明拦截对照（四种伪造）

| 伪造类型 | 拦截闸 | 拦截原因（verdict.reasons） |
|---|---|---|
| 无签名 | 身份闸 | signature verification failed |
| 坏边界 boundary='L9'（签名有效） | 军法闸 | BOUNDARY_VALID: invalid boundary 'L9' |
| 战报 101 字（签名有效） | 军法闸 | SUMMARY_BOUND: summary length 101 exceeds 100 |
| L2a 无证据（签名有效） | 军法+边界闸 | EVIDENCE_L2A + boundary 双记 |

**判决：通过。** 4/4 拦截，且后三种的签名全部有效——即"节点自己签自己的谎言"场景，验证门与身份无关地单独裁决内容违规。

## E03 崩溃收养

构造死现场（死 pid + 120 秒前 startSec + 120 秒前 mtime）→ adopt() 三证据齐备收养 → 任务重派回 inbox → 新节点认领 → 完成。

**判决：通过。** 收养 1/1，三证据（pidDead/startSecExpired/mtimeExpired）全真，任务 9 重派完成。

## 复核教训（实验构造 bug 两条，协议本身零 bug）

1. 实验脚本未预建 inbox 目录 → 补 mkdir（脚本 bug）；
2. 伪造信封"先重签后改 id"导致签名绑定旧 id、验签失败 → 改为先定 id 再签（脚本 bug）。
   此 bug 反而是协议严格性的意外证明：id 被篡改 → 验签必失败，签名对信封全字段（含 id）绑定生效。

## 单测

`node --test`：17/17 绿（签名/军法/租约/收养/canonical/规则可升级/register/constants）。
