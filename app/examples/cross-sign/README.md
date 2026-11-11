# cross-sign 示例

- 受信根：Root A（独立指定）。Root B 故意放进中间包，模拟交叉签发的另一侧。
- `Intermediate CA X` 的同一把公钥被 Root A、Root B 分别签发（真正的交叉签发），另有一张同 DN、不同密钥的陈旧证书；后者验签必然失败，必须按签名区分。
- 期望：枚举出两条候选路径，只有 leaf→I(Root A 签)→Root A 通过；leaf→I(Root B 签) 因 Root B 不受信而失败，Root B 上方作为缺失/不受信签发者单独指出。
- 校验时间：2026-11-11T00:00:00+00:00
