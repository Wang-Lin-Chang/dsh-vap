# 控制台乱码消弭 —— 交付报告（enc-brief）

## 结论

**完成。** 在 Windows 老控制台（GBK cp936）下，程序自动把码页自愈为 UTF-8 后直出中文，
用户零操作；`VAP_LANG=zh|en` 逃生舱可强制语言；文案全部收敛进双语字典，零内联中文字面量，
零第三方依赖。

## 交付物对照

| 交付物 | 状态 | 说明 |
|---|---|---|
| `console-adapter.mjs` | ✅ | `parseCodePage` / `detectConsoleLang`（纯函数可注入）/ `adaptConsole`（isTTY 短路 + chcp.com 直调 + 行尾数字解析 + 936/54936 自愈 chcp 65001）/ `createT`（缺 key 抛错）/ `DICT`（153 键） |
| 四 bin + process-guard 文案迁移双语字典 | ✅ | 全部含中文文案经 `t()` 取值；`parseCliArgs`/`renderHelp`/`cliArgs` 支持可选 `t`（缺省 zh，旧接口不破） |
| `tests/console-adapter.test.mjs` | ✅ | 裁决表全覆盖 / 三种输入解析 / 缺 key 抛错 / 字典 zh-en 对等 + en 纯 ASCII，共 19 用例 |
| README 双语 VAP_LANG 逃生舱 | ✅ | `README.md` 与 `README.zh-CN.md` 各加一句 |

## 验收（硬性）逐条

1. **测试全绿**：`node --test` = **217 通过 / 0 失败**（旧 198 个一个不破 + 新增 19 个）。
2. **cp936 本机实测**：本机 `Active code page: 936`；真实 chcp.com 输出解析为 936；
   TTY 检测 → `{ lang:'zh', reason:'chcp-936' }`；自愈 `chcp 65001` 后码页实测 936 → 65001，
   中文以 UTF-8 直出、无乱码。
3. **VAP_LANG=en**：四 bin `--help` 实测输出全英文（纯 ASCII）。
4. **文案零内联中文字面量**：grep `bin/*.mjs` 的中文只剩注释；字典唯一载体为
   `console-adapter.mjs` 的 `DICT`。
5. **零第三方依赖**：新增文件仅 import `node:path` / `node:child_process`；
   `package.json` 无 dependencies、无 node_modules。

## 技术要点

- **裁决优先级**：`VAP_LANG` → 非 TTY（字节透传 UTF-8）→ 非 win32（默认 UTF-8）→
  65001（中文）→ 936/54936（自愈 chcp 65001 后中文）→ 其余码页（英文纯 ASCII）。
- **自愈失败降英文**：`execFileSync(chcp 65001)` 异常被吞掉并 `{ lang:'en' }`，绝不崩溃。
- **en 侧纯 ASCII**：任何非 CJK 码页下都安全（含 ✓/✗/≤/→/—— 等符号均被 ASCII 替代）。
- **字典防漂移**：`createT` 缺 key 抛错 + 缺语言值抛错；测试强制 zh/en 对等与非空。

## 文件清单

- 新增：`console-adapter.mjs`、`tests/console-adapter.test.mjs`、`progress-enc.md`、`report-enc.md`
- 修改：`bin/process-guard.mjs`、`bin/vap-gateway.mjs`、`bin/vap-relay.mjs`、`bin/vap-node.mjs`、
  `bin/vap-send.mjs`、`README.md`、`README.zh-CN.md`
