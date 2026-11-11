# all-fail 示例

默认叶子 `client.pathlen`：根 pathLen=1、Tight pathLen CA pathLen=0，其下方又有一级签发 CA → pathLen 违规。

替换叶子可分别复现：
- alt-leaf-expired-issuer：同 DN 候选一张有效、一张 2020 年过期；过期链单独失败。
- alt-leaf-no-keycertsign：签发 CA 的 KeyUsage 未置位 keyCertSign。
- alt-leaf-missing-issuer：Orphan CA 的签发者 Missing External Root 未提供。
- 校验时间：2026-11-11T00:00:00+00:00
