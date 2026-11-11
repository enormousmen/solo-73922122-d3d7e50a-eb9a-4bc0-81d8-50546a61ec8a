# mTLS 证书链离线诊断工具（mtls-chain-doctor）

内网 mTLS 运维排障场景：网关拒绝客户端证书时，区分两类根因——

1. **中间证书缺失**：叶子/中间证书的 issuer 在上传包中根本不存在；
2. **交叉签发选链错误**：存在同名（subject DN 相同）但密钥不同、或同一公钥被不同根交叉签发的多张证书，需要**验签后区分**，且一条候选链失败不能阻止其他链被枚举。

全部计算在本机离线完成，不发起任何网络请求，不检查吊销（CRL/OCSP）与证书用途（EKU）。

## 进程模型与并发保护

Web 服务只运行**一个 uvicorn 进程**，本身**不做任何 PEM 解析与证书链计算**。每份诊断请求都由一个**独立的一次性子进程**（`app/worker.py`，以 `python -I` 隔离模式启动）完成，主进程只负责非阻塞的管道通信：

- 全服务最多同时接纳 **2 份**计算（`app/runner.py::MAX_CONCURRENT_COMPUTATIONS`），**没有等待队列**：名额已满时新请求**立即**返回 `503 服务繁忙`，不排队、不阻塞其他访问；
- 取得名额后 **3 秒**（`COMPUTE_TIMEOUT_SECONDS`）未完成即返回 `504 计算超时`，并终止、回收对应子进程后才让出名额；
- 客户端断开（关闭页面/中止请求）会同步停止其计算子进程；
- 超时、断连或子进程异常退出时，先关闭管道、等待进程**确实退出**再释放名额——取消协程等待不会代替终止计算；
- 计算期间首页、示例接口等非计算路由照常可用；任何失败都不会返回半成品诊断结论（HTML 渲染专门的错误页，JSON 返回错误码）。

| HTTP 状态 | 场景 | JSON `code` |
| --- | --- | --- |
| 503 | 2 个计算名额已满（立即拒绝） | `capacity_exhausted` |
| 504 | 计算超 3 秒，或客户端断开 | `compute_timeout` / `client_disconnected` |
| 502 | 计算子进程异常退出/输出无法解析 | `worker_failure` |
| 400 | PEM 等用户输入不合法（子进程判定） | — |

## 诊断范围与规则

- 输入：1 张客户端证书（leaf）+ 1 个无序中间证书 PEM 包 + 1 张独立指定的受信根 PEM；
  三类输入去重后**总计最多 12 张**证书。
- 签名策略：**仅支持 RSA PKCS#1 v1.5 / SHA-256**（OID `1.2.840.113549.1.1.11`），其他算法在全局提示与逐链结果中标为不支持。
- 从叶子出发 DFS 枚举**所有无环候选路径**（含环时只记录无环前缀，保证终止；有枚举上限保护）。
- 同名签发者必须先验证签名：同 DN 但验签失败的证书不会进入任何链，并在「同名签发者歧义」专区列出。
- 对每条候选链独立检查，任一链失败不影响其他链：
  - 每张证书在给定校验时间的有效期（notBefore 含、notAfter 不含）；
  - 每个签发者 `BasicConstraints cA=TRUE`；
  - `KeyUsage` 扩展**存在时**必须包含 `keyCertSign`（不存在不强制）；
  - 每个签发者的 `pathLenConstraint`（RFC 5280：只统计其下方非自颁发的中间 CA；终端实体叶子与自颁发中间证书不占 pathLen）；
  - 链必须终止于独立指定的受信根（根的自签名同样验证）。
- 输出：存在通过链时展示第一条通过的链；全部失败时逐条列出候选链、失败位置（链内下标）、错误码与原因；缺失签发者单独专区列出（含「同名但验签失败」明细）。

## 快速开始（Docker Compose）

```bash
docker compose up --build -d
# 浏览器入口
open http://127.0.0.1:8080/        # Linux 可改用 xdg-open
```

页面上点击内置示例 `cross-sign` / `all-fail` 即可自动载入 PEM 与校验时间，直接点「开始诊断」。
容器以非 root 运行，只读根文件系统、丢弃所有 Linux capabilities、`no-new-privileges`，端口仅绑定回环地址。

停止：`docker compose down`

## 本地直接运行

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 浏览器上传页面（含并发/超时说明） |
| POST | `/diagnose` | multipart 表单：`leaf`、`intermediates`、`root`、`validation_time`（ISO 8601，无时区按 UTC），返回 HTML 结果页；繁忙/超时/进程异常渲染对应错误页（503/504/502） |
| POST | `/api/diagnose` | 同入参，返回 JSON 诊断结果；失败返回带 `code` 的错误 JSON（503/504/502/400） |
| GET | `/api/examples/{name}` | 取内置示例的 manifest 与 PEM 文本 |
| GET | `/examples/{name}` | 303 跳转并由前端自动填充示例 |

## 内置示例

由 `scripts/generate_examples.py` 离线生成（一次性 RSA-2048 临时密钥）：

- **cross-sign**：`Intermediate CA X` 的同一公钥被 Root A / Root B 交叉签发，另含一张同 DN 不同密钥的陈旧证书；Root B 被放进中间包但不是受信根。预期两条候选链，一条通过、一条因终止于不受信根而失败。
- **all-fail**：默认叶子触发 pathLen 违规；替换 `alt-leaf-*.pem` 可分别复现签发者过期、KeyUsage 缺 keyCertSign、缺失签发者三种失败。

重新生成：`python3 scripts/generate_examples.py`

## 测试

```bash
pip install -r requirements.txt
python3 -m pytest -q
```

覆盖：简单链通过、中间证书缺失、交叉签发同名验签区分、不因首条失败中止枚举、有效期边界、pathLen 与自颁发豁免、KeyUsage、非 CA 签发、签名算法白名单、环终止、12 张上限、去重、受信根自签名检查、Web/API 端到端；以及名额池立即拒绝与释放、503 饱和（含首页/示例仍可用）、504 超时终止回收、客户端断连中止、子进程崩溃/坏输出 502、输入错误 400、真实单进程 uvicorn 冒烟。

## 目录结构

```
app/
  diagnostics.py        # 核心：PEM 解析、建图、全路径 DFS、逐链约束校验（在子进程内执行）
  worker.py             # 一次性诊断子进程入口（python -I，stdin/stdout 行分隔 JSON 协议）
  runner.py             # 计算名额池(上限2、无队列) + 子进程生命周期(3s超时/断连/异常回收)
  result_adapter.py     # 子进程 JSON 结果 -> 模板可用的属性访问适配
  main.py               # FastAPI 路由（HTML + JSON API，503/504/502/400 映射）
  templates/            # Jinja2 页面（含错误页）
  static/               # CSS 与示例载入/提交脚本（前端展示繁忙与超时）
  examples/             # 内置交叉签发/全失败示例 PEM
scripts/generate_examples.py
tests/
Dockerfile, docker-compose.yml, requirements.txt
```
