# dsh-vap 开源清理进度（progress-clean）

## 结论

开源清理全部完成：开发档案已删、内部术语已中性化、包已改名、测试全绿。

## 1. 开发档案删除（32 个文件）

删除根目录与各 phase 子目录下的全部开发档案（brief*/progress*/fix-batch*-brief/polish-brief/enc-brief）。

- 根目录 16：brief.md、brief-ring.md、brief-ring2.md、enc-brief.md、fix-batch1-brief.md、fix-batch2-brief.md、fix-batch34-brief.md、polish-brief.md、progress.md、progress-ring.md、progress-ring2.md、progress-fix1.md、progress-fix2.md、progress-fix34.md、progress-polish.md、progress-enc.md
- phase0、phase0.5、phase1、phase2、phase3、phase4、phase5、phase6 各目录 16：brief.md 与 progress-phase*.md（8 个 phase 目录 × 2）

注：简报原文写「31 个」，按删除规则（所有 brief*/progress*/fix-batch*-brief/polish-brief/enc-brief）实际匹配为 32 个——多出的 1 个为 phase0.5/brief.md（phase0.5 亦属 phase 子目录，且 phase0.5/progress-phase05.md 一并按规则删除）。

## 2. 内部术语中性化（仅保留文件，逐处 edit 工具修改）

所有内部代号与流程黑话改为中性表述（交叉审计 / 独立复核轮 / 独立复核 / 交叉复核 / 多路独立推演 / 复核），涉及文件：

- FIXLIST.md
- COMPETITORS.md
- report.md
- ROADMAP-OUTER.md
- vap-core.mjs
- vap-spec.md
- phase0.5/bootstrap-forge.mjs（注释改为「独立复核抽查」）
- phase0.5/DESIGN.md
- phase0.5/P05-REPORT.md
- phase0.5/experiments/phase05-experiment.mjs
- phase0.5/experiments/phase05-results.json
- phase1/IDENTITY.md
- phase1/report-phase1.md
- phase5/DESIGN.md
- phase5/P5-REPORT.md
- phase6/DESIGN.md

## 3. package.json

- name 由 `vap` 改为 `dsh-vap`（npm 上 `vap` 已占用）。
- 新增 files 白名单：README.md、README.zh-CN.md、LICENSE、CHANGELOG.md、vap-spec.md、`*.mjs`（根目录）、bin/、bridges/、phase*/DESIGN.md、phase*/P*-REPORT.md、phase*/experiments/*.mjs、experiments/、tests/、laws.json。
- description 保持。

## 4. 测试

- `node --test`：217/217 全绿。
- 修正 tests/deploy-regression.test.mjs 第 427 行包名断言（`vap` → `dsh-vap`）。

## 5. 校验

- 敏感词 grep 全库零命中（clean-brief.md 为指令源，已按约定最后删除）。
- 坏词清单：交付文件零命中（仅 ACCEPTANCE.md 的清单定义处与 report-fix2.md / report-fix34.md 的零命中核验说明，均非交付文件）。
- README 无内部术语。

## 6. 收尾

- clean-brief.md 已删除。
- 本文件为本次清理的进度记录。
