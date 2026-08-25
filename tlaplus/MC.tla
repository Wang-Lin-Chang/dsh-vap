---- MODULE MC ----
\* 模型模块：供 TLC 装载。常量在 MC.cfg 中赋值（N=4 起步）。
\* 运行方式（待 Java/TLC 就绪后）：
\*   java -cp tla2tools.jar tlc2.TLC -config MC.cfg MC
\* 本模块只 EXTENDS 规格，使 Spec / TypeOK / 不变式 / 活性性质对 TLC 可见。

EXTENDS VAPConsensus

================================================================================
