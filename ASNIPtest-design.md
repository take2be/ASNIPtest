# ASNIPtest 优化版 — 设计基线（DESIGN BASELINE）

> **性质**：纯设计规格，非代码。逐步定稿追加，封口即落盘。
> **用途**：新回话第一件事 load 本文件作为已锁死基线，从后续未完成阶段继续。
> **节奏**：先定设计、逐阶段深究锁定后才写码，未锁定前不动笔。

---

## 0. 项目定位

```
目标：按 ASN 号 → 全端口扫描 → 找出第三方 Cloudflare 反代 IP（优选 IP）
独立扫描报告工具，不绑定 KV / 不写 yxip_pool / 纯本地报告
跨平台：Win / WSL / Linux / macOS 通吃（不硬编码 Windows 路径）
缓存目录：脚本同级 ./cache/（不用 $LOCALAPPDATA）
```

## 0.1 整体管线（6 阶段 + 引擎骨架）

```
① ASN → CIDR        输入为 ASN 时取该 ASN 广播的所有 IPv4 段；输入为 IP 段时直接使用（跳过拉取）
② masscan 端口发现  (强制) 全端口 SYN 扫描，找开放代理服务的 IP:Port
③ verify 插件       (可插拔) 判定 IP:Port 是否为 CF 反代节点
④ enrich            ip-api 查 ASN+国家，过滤 Cloudflare 官方 ASN
⑤ speedtest         curl 直连测延迟+下载速度
⑥ output            富列报告 CSV（IP|PORT|TLS|ALPN|Latency|Download|ASN|Country）

支撑：统一任务队列引擎 + 水位控制 + 缓存/断点续跑 + 跨平台 ./cache
```

---

## ① ASN → CIDR（已封口）

### 实现方式
- **数据源故障切换（非负载均衡）**：
  - 主：RIPEStat `https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}`
  - 备：BGPView `https://api.bgpview.io/asn/AS{asn}/prefixes`（仅主源查不到/超时才切）
  - 可选第三备：bgp.he.net（不强制）
- **只取 IPv4**：RIPEStat 过滤含 `:` 的段；BGPView 直接读 `ipv4_prefixes`
- **重试优先于切换（坑B）**：RIPEStat 超时 → 重试 2 次（指数退避）→ 仍失败才切 BGPView
- **合法性校验（坑C）**：`ipaddress.IPv4Network(p, strict=False)` 校验，非法段丢弃
- **过滤不可扫描网段（坑D）**：用 ipaddress 内置判定，近零成本
  - `.is_private`（10/8, 172.16/12, 192.168/16 等）
  - `.is_loopback`（127/8）
  - `.is_link_local`（169.254/16）
  - `.is_reserved`（0.0.0.0/8, 240/4 等）
  - `.is_multicast`（224/4）
  - `.is_unspecified`（0.0.0.0/8）
  - 单独处理 `100.64.0.0/10`（CGNAT，is_private 不一定覆盖，实现时确认）
- **去重（保留，便宜）**：`set` 存 CIDR 字符串，多 ASN 重叠段不重复扫
- **本地缓存 + TTL 24h（按 ASN 分键）**：
  - `cache/cidr_AS{asn}.txt` = 解析后的 CIDR 列表（一行一段）
  - 非 `--force` 直接读缓存，不发 HTTP
  - **不存原始 JSON**（用户确认无必要）
- **代理处理（坑A）**：① 步查 RIPEStat 等 API 时**尊重 `*_PROXY`**（本地 WSL 在 GFW 下可能要走代理才稳）；与 ②masscan / ⑤speedtest 的「清掉代理直连」刚好相反，两处分开写清楚

### 输出（喂给 ②）
干净 CIDR 列表文件（已去重 + 过滤不可扫网段）

---

## ② masscan 端口发现 + 验证流水线（已封口，含引擎骨架）

### ②.1 引擎骨架原则（②确立，③④⑤⑥继承）
1. **统一任务队列**：流动单位 = IP:Port 任务，非 Block
2. **水位控制**：待验队列 >HIGH 暂停起新 Block，<LOW 恢复
3. **Plan 与调度分离**：Plan（块划分）确定性来自输入；调度（何时起块）响应运行时 → 只影响时序不影响划分
4. **各级吞吐量统计**：每级 items/s 实时显示，定位瓶颈
5. **流式优先**：能边解析边入队就不等整文件（受 masscan 格式约束）

### ②.2 输入
全局一次性输入：ASN + 端口集（所有 Block 沿用，切块只切 CIDR 不切端口）

### ②.3 CIDR 承接
- 原样进 ②，不拆 /24（masscan `-iL` 直接吃 CIDR，内部自己展开地址）
- 已去重 + 过滤不可扫描网段（来自 ①）

### ②.4 Plan（首次生成，持久化，Resume 复用）
- **一次性全量规划（选项 X，纯输入驱动）**：run1 用「输入数据」(CIDR 数量 / 密度 / 前缀分布) 确定性算好所有 Block 边界 → 写 `scan_plan.json`
- **不依赖运行时**（吞吐 / 积压 / CPU）→ 同输入必出同划分
- 边界记录：`blocks:[{index, cidr_range:{start_idx,end_idx}, block_input_hash, cidrs_file}]`
- **原子落盘顺序（不可反）**：先写 `scan_plan.json.tmp` → fsync → `os.replace` → `scan_plan.json`；之后才 materialize 各 `block_NNN_cidrs.txt` 并起 masscan
  - 崩在 Plan 落盘前 → 重规划结果同，无竞态
  - 崩在落盘后 → 边界已固化，Resume 复用
- **动态切块只依赖输入数据，不依赖运行时**：运行时性能只影响「调度（何时起下一块）」，不影响「Plan（块怎么划）」

### ②.5 架构
- **单生产者（masscan 串行扫块）+ 多消费者（verify 线程池）**
  - masscan 本身高性能，多开反抢网卡/socket 导致丢包；真正耗时的是 verify（TLS/HTTP/openssl I/O 密集）
- Block 扫完 → 边解析边把 **单个 IP:Port 任务** 入 Queue（非整块入队，负载均衡）
- verify 线程池 get 后调 `verifier.verify(ip, port)`

### ②.6 水位（Watermark / Backpressure）
- `Queue.qsize() > HIGH(默认10000)` → 暂停提交新 Block（已扫的不停）
- `< LOW(默认5000)` → 恢复
- 检查点在「块 N 入队后、起块 N+1 前」
- 注：背压属调度策略（Performance Optimization），**不 bump SCAN_SCHEMA**

### ②.7 masscan 调用
```
sudo masscan -iL block_NNN_cidrs.txt -p <全局端口集> \
  --rate <自适应> -oJ(或-oL, 视流式需求定) --wait 5 --max-retries 1
```
- 端口：默认 `443,2053,2083,2087,2096,8443`（CF 加密端口）；`--ports` 任意端口/范围覆盖
- rate 自适应：WSL2 → 2000；其他 Linux(root) → CPU核×1000
- 非 root 自动加 sudo
- **masscan 为强制依赖，不可跳过/不可降级 Python TCP**

### ②.8 masscan 产物（原子写）
- 写 `block_NNN.json.tmp` → 扫完（退出码0且非空）→ `os.replace` → `block_NNN.json`
- 崩溃留 `.tmp` 不误判"扫完"

### ②.9 verify 产物 + checkpoint（双阈值 + 原子写）
- 每「累计 500 个已处理任务（成功+失败都算）」**OR**「距上次 checkpoint > 30s」
  → 全量写 `block_NNN.cf.tmp.new` → fsync → `os.replace(.new, .cf.tmp)`
- 本块验完（含 0 任务）→ rename `.cf.tmp` → `block_NNN.cf.txt`
- `.cf.tmp` 格式：每行 `IP:Port 状态位(0/1)`，不含任何富字段
- **空 Block（0 开放端口）也写空 .cf.tmp→.cf.txt**（防 Resume 死循环）

### ②.10 Resume 机制（IP:Port 级，非 Block 级）
- 读 `scan_plan.json` → 比对 `plan_hash`
- 对 Plan 中每块：
  - 有 `.cf.txt` → 跳过
  - 有 `.json` 无 `.cf`(含仅 `.tmp`) → 只重 verify，不重扫
  - 两都无 → 重扫
- 读 `.cf.tmp` → 全部(0/1)进 completed set；**未出现过的才重验**（不整块重跑）
- 与 verify 插件解耦：Resume 只看"验过没"，不关心当初用什么插件
- **强拒（语义类，plan_hash 不符即拒，提示重扫）**：
  - `asn / cidr_source / ports_hash / verify_method /`
  - `SCAN_SCHEMA / VERIFY_SCHEMA / RESUME_SCHEMA`
  - 全部块的 `cidr_range` + `block_input_hash`
- **软提示（环境类，全部忽略，仅排查用）**：
  - `tool_version / verify_workers / scan_workers / start_time / hostname / python_ver / masscan_ver / openssl_ver / os`
- `ports_hash`：端口规范化（排序+合并连续区间）→ canonical string → SHA256（443,8443 与 8443,443、1-1024 与 1,2..1024 视为同）
- `block_input_hash` = `block_NNN_cidrs.txt` 的 SHA256（代表 Block 输入身份）

### ②.11 scan_plan.json 结构
```json
{
  "resume_identity": {
    "asn": "...",
    "cidr_source": "RIPEStat",
    "ports_hash": "sha256...",
    "verify_method": "openssl",
    "scan_schema": 1,
    "verify_schema": 1,
    "resume_schema": 1,
    "blocks": [
      {"index": 1, "cidr_range": {"start_idx": 0, "end_idx": 500}, "block_input_hash": "sha256...", "cidrs_file": "block_001_cidrs.txt"},
      ...
    ]
  },
  "runtime_info": {
    "created_at": "...",
    "tool_version": "...",
    "verify_workers": 256,
    "hostname": "..."
  }
}
```
- `OUTPUT_SCHEMA` **不进** Plan（不参与 Resume）

### ②.12 吞吐统计
- 每级维护计数器 + 时间戳，实时算速率显示（masscan / verify 本级；enrich / speed 待 ③④⑤ 设计时挂入）

### ②.13 本步职责边界
- ② 步只负责"是不是 CF 反代"（状态位 0/1），**不测速、不取富字段**
- 富字段（TLS版本 / ALPN / ASN / 国家 / 延迟 / 速度）全留给 ③④⑤⑥ 后续阶段
- 产物 = 已验证 CF 反代 IP:Port 状态集

### ②.14 verify 并发
- 默认 `min(CPU核×32, 256)`，`--verify-workers` 手动覆盖
- `verify_workers` 仅记 meta（Runtime Info），不参与 Resume 判定

---

## 跨步设计原则（贯穿全项目）

1. **只有影响结果的改动才 bump SCAN_SCHEMA**：背压 / 调度 / 线程数 / 块分发 / 扫描顺序 / 日志 / UI / 性能优化 / 修 panic → 全不 bump
2. **Block 写"内容生成"不写"切块/split/chunk/partition"**：block_size 变化只是任务划分，Resume 应继续
3. **meta 分两类**：Resume Identity（强拒比对）/ Runtime Info（仅记录忽略）
4. **OUTPUT_SCHEMA 独立于 Resume**：不进比对，也不强制进 meta
5. **Don't freeze too early**：schema 先宽松（常量=1，括注原则），等 ③④⑤⑥ 全定稿再出《Schema Mapping》文档固化字段级映射
6. **Schema Version ≠ Tool Version**：工具版本反映发布，Schema 只反映数据兼容性，两者解耦
7. **Plan 与调度分离**：Plan 确定性来自输入；调度响应运行时只影响时序
8. **动态切块只依赖输入数据不依赖运行时**
9. **Enrich 是增强模块不是判定模块（架构铁律）**：④ 可以补充元数据（ASN/国家/组织）、可以过滤 Cloudflare 官方 ASN，但 **永远不能改变 ③ 的 Verify 结果，永远不能因查询失败丢弃 IP 或阻断后续流水线**。ASN/国家全查不到 → 显示 `ASN=-`/`Country=-`，IP 仍进 ⑤⑥。

### Schema 常量（占位，当前值=1）
```python
SCAN_SCHEMA   = 1  # 扫描结果语义变化时 bump（CIDR生成/Block内容生成/masscan解析/去重）
VERIFY_SCHEMA = 1  # 验证结果语义变化时 bump（CF判定规则/插件接口/证书解析）
RESUME_SCHEMA  = 1  # Resume 文件格式变化时 bump（.cf.tmp行格式/.meta.json结构）
OUTPUT_SCHEMA = 1  # 输出格式语义变化时 bump（不参与 Resume）
```
- 括注为方向，非锁死字段清单
- 《Schema Mapping 文档》待 ③④⑤⑥ 全定稿后回头固化

---

## ③ verify 插件（定稿 v1）

### ③.1 职责边界（与 ②.13 对齐）
- ③ 只回答一个问题：**「这个 IP:Port 是否是一个 Cloudflare TLS 端点（呈现 Cloudflare 证书 / 行为像 CF 边缘）」** → 输出 0/1 决策。
- **不区分「第三方反代」与「Cloudflare 官方边缘」**：二者都呈现 CF 证书，③ 一律判正；「第三方」的区分留给 ④ 的 ASN 过滤（剔掉 CF 自身 13 个 ASN）。③/④ 职责干净分离。
- ③ 不采 ASN / 国家 / 延迟 / 速度（留给 ④⑤）。TLS 版本 / ALPN 归属见 ③.7。

### ③.2 可插拔接口契约 + 统一返回值（标准化）
> **返回值标准化（核心设计）**：所有插件返回**同一结构**，主流程永远只认 `result` 字段（PASS/FAIL/UNKNOWN），插件身份与判定原因都是插件自己的实现细节。新增 QUIC / ECH / API 等插件时主流程零改动。

```python
VERIFIERS: dict[str, VerifyPlugin]   # mode -> 插件实例
# 注：②.5 / ②.9 的 verifier.verify(ip, port) 即本 decide()
# 标准化 reason 枚举（所有插件从中选，禁止自由字符串）
REASON = Literal[
    "subject_match",      # TLS leaf subject O 含 cloudflare（主判据）
    "issuer_match",       # TLS issuer 组织含 cloudflare（辅，覆盖 CF 自有 CA）
    "http_cf_ray",        # HTTP 响应含 CF-RAY 头
    "server_cloudflare",  # HTTP Server 头 == cloudflare
    "timeout",            # 连接/TLS/HTTP 超时
    "tls_error",          # TLS 握手异常（非超时，如拒签）
    "no_certificate",     # 握手成功但无证书 / 拿不到 peer cert
    "connection_refused", # 连接被拒
    "conn_error",         # 其他连接错误
]
CONFIDENCE = Literal["high","medium","low","external"]  # 证据强度，仅供统计/排查
class VerifyResult:
    result: Literal["PASS","FAIL","UNKNOWN"]   # 主流程唯一消费字段
    method: str        # 实际判定插件：tls / http / openssl / api / quic ...
    reason: REASON     # 判定依据，必须从枚举选
    confidence: CONFIDENCE  # 证据强度：subject_match/issuer_match/quic→high；http_*→medium；api→external
    extras: dict       # 旁路采集（顺手采，不参与判定）：tls_version / alpn / cipher
class VerifyPlugin:
    name: str
    def decide(ip, port, cfg) -> VerifyResult   # 单次连接内完成判定+顺手采 extras
```
- `.cf.txt` 只取 `result` 映射为 0/1：`PASS→1`，`FAIL/UNKNOWN→0`（遵守 ②.13，不持久化富字段）。
- `extras`（TLS版本/ALPN/cipher）**在同一 deciding 连接上顺手采**，不另起二次握手；仅对 `PASS` IP 落到 `block_NNN.tls.txt`（⑥ 输入），不回写 `.cf.txt`。
- `UNKNOWN` 与 `FAIL` 在 `.cf.txt` 同为 0；区别仅用于统计（探测失败率 vs 明确非 CF 率）。
- `method` / `reason` / `extras` 不参与主流程判定，仅供统计与下游 enrich/输出。
- 换算法 = 加一个插件类 + 注册进 `VERIFIERS`；主流程零改动。

### ③.3 候选插件与判定信号
| 插件 | 实现 | 外部依赖 | 判定信号 | 备注 |
|---|---|---|---|---|
| `tls` | 纯 Python/Go TLS 握手 + 证书解析 | 无 | **辅助判定**：leaf subject O / CN / SAN 含 "cloudflare" 作辅助信号与诊断记录；**不作主判定**（实测真实 CF 证书 subject O 常为空，cloudflare 在 CN/SAN，且证书层对 GFW 阻断目标取不到） | 轻量；被墙时取不到证书 |
| `openssl` | 子进程 `openssl s_client` 解析全链 + TLS 版本 + ALPN | 需 openssl 二进制 | 同上 + 完整链 + 容忍拒签证书 | 最完整；Windows 默认可能无二进制 → 非默认 |
| `http` | 纯 Python 在 TLS 套接字上发 `GET /`，读响应头 | 无 | `CF-RAY` / `Server: cloudflare` | 行为级确认，用于 TLS 无法明确判定时补充；需服务端应答 HTTP |
| `api` | 调 `api.090227.xyz/check` | 网络+第三方 | 远端判定 | **默认关**；限流/依赖 |
| `hybrid` | **状态机**（见下）：TLS PASS/FAIL 即结束；仅 TLS UNKNOWN 才复用同一条已建连接发 HTTP 补充 | 取决于子插件 | 以上并集 | 召回最高，且绝大多数目标仅一次握手 |

> **hybrid 状态机（短回路，HTTP 永不推翻 TLS）**：
> 1. `tls` 判定：
>    - `result == PASS` → 结束，收（method=tls，confidence=high）
>    - `result == FAIL` → 结束，拒（method=tls）【**FAIL 不触发 http**，证书明确非 CF 即信，省一次请求】
>    - `result == UNKNOWN` → 进入 2
> 2. `http` 在 **tls 已建立的同一条 TLS 连接**上发 GET 补充判定 → 返回 `PASS`/`FAIL`/`UNKNOWN`（method=http，confidence=medium）
> - **HTTP 永远不是去「推翻」TLS 的结果，只解决 TLS 无法判断的情况**。因此不会出现「到底谁优先」的歧义，架构干净。
> - **强约束（禁止重复 TLS 握手，B）**：hybrid 模式下 `http` 必须复用 `tls` 阶段已建立并握过手的 socket，**严禁重新 connect + 重新 TLS 握手**。理由：两次握手可能落到不同连接状态甚至不同后端，结果不一致；且重握浪费。tls 插件须把已建立 socket 句柄交给 http 阶段（hybrid 契约的一部分）。

> **判定信号说明（不绑定特定 CA，实测修正）**：现代 Cloudflare 反代节点经 HTTP 层响应会带 `CF-RAY` 头或 `Server: cloudflare`。**主判定信号 = HTTP 层 `CF-RAY` 非空 或 `Server: cloudflare`**（行为级，最稳，已被真实样本验证为唯一稳定信号，原项目 `cf-scanner` 即采用此逻辑）。TLS 证书层（subject O / CN / SAN 含 "cloudflare"）仅作**辅助/诊断记录**，不作主判定——实测真实 CF 边缘证书 subject O 常为空、cloudflare 在 CN/SAN，且 GFW 直连阻断时证书层根本取不到。tls 插件职责降级为「顺手采证书信息供诊断」，不再承载 PASS/FAIL 主判定。

### ③.4 实现语言与架构（实测规模修正）
- **运行环境锁定**：用户操作端为 Windows git-bash，但**实际运行端为 Linux（WSL2 或境外 VPS）**，无 Windows 原生运行需求。扫描规模百万级 (IP:port)（单 ASN 如 AS906 即 25万~100万 target），验证热路径需高并发。
- **架构 = C（Python 编排 + Go 验证二进制）**：参照同领域已跑通原项目 `ASNIPtest`（run.py 编排 + cf-scanner Go 验证 + verify.py API 精筛）收敛出的形态：
  - **Go 验证模块（对应③）**：高并发 TLS 握手 + HTTP `CF-RAY`/`Server` 判定，移植原项目 `isCloudflareProxy` 逻辑；单二进制 `cf-scanner` 可被 Python 编排层调用。goroutine 原生 500+ 并发，百万级验证分钟级完成。
  - **Python 编排层（对应①②④⑥）**：ASN→CIDR→masscan→分块/Resume/④enrich/⑥输出，表达力强、迭代快；调用 Go 验证二进制。
  - **⑤ 测速**：借原项目 run.py 的 curl `--connect-to` 思路，但**按设计文档⑤标准完整实现（socket 三步法、3次中位数延迟、1MB Range 下载、复用③连接上下文、CF Challenge 页检测→DOWNLOAD=0），不打折扣**——本地运行时测速是核心产出。
- **不做纯 Go（A）也不做纯 Python（B）**：纯 Go 写流水线 glue 啰嗦；纯 Python 在百万级验证并发天花板低（已算：200线程≈83分钟 vs Go≈3分钟，差25~40倍）。
- `openssl` 子进程 / `api` 精筛 维持原设计（api 默认关，可接 `api.090227.xyz/check` 作二次精筛）。

### ③.5 SNI / Host 策略（实测封口，移植原项目）
- **锁死**：验证阶段发送 `SNI = cloudflare.com`、`Host = www.cloudflare.com`（移植原项目 `cf-scanner` main.go:25-26）。理由：真实样本验证表明，向 CF 反代边缘发此 SNI/Host 能稳定触发其默认证书与 `CF-RAY` 响应头，召回最高；自定义客户域名 SNI 反而拿不到 CF 默认证书。
- 不硬编码任何「特定客户网站」域名（cloudflare.com 是 CF 自身域名，作探测探针，非目标站点）。
- `http` 插件在已建 TLS 连接上发 `GET /` 时，`Host` 头用 `www.cloudflare.com`，读取 `CF-RAY` / `Server` 响应头判定。

### ③.6 超时与重试（热路径）
- **超时（默认参数，非协议锁定）**：
  - TCP connect 超时默认 **2s**；TLS 握手总超时默认 **5s**；HTTP 读超时默认 **5s**。
  - 仅作 `--conn-timeout` / `--tls-timeout` / `--http-timeout` 默认值；**不写死进协议，调整不影响 `VERIFY_SCHEMA`**。
- **verify 无重试**：单次超时/异常 → `result=UNKNOWN`（记 `reason=timeout`/`conn_error`，等价非 CF）。理由：扫描量极大（整 ASN 开放端口），重试翻倍耗时；masscan 已确认端口开放，verify 为概率性探测，漏检可在后续重扫弥补。
- 线程池内每连接独立 socket + 异常隔离，单点失败不影响其他任务。

### ③.7 TLS 版本 / ALPN / cipher 归属 —— 顺手采，不二次握手
- 遵守 ②.13：② 热路径 `.cf.txt` 只存 0/1，不采 TLS/ALPN。
- 但 TLS 版本 / ALPN / cipher 是 deciding 握手的内生产物，在 **③ 的 `decide()` 同一连接上「顺手采」进 `extras`**（见 ③.2），**绝不为了拿这些字段再握一次手**。
- 仅对 `PASS` IP 的 `extras` 落独立产物 `block_NNN.tls.txt`，作 ⑥ 输入，**不回写 `.cf.txt`**。
- `extras` 只采集、不参与 ③ 判定；④⑤ 也不得依赖 ③ 的 extras（各自独立）。

### ③.8 与 Resume / Schema 的映射
- `verify_method`（字符串：tls/openssl/http/api/hybrid…）∈ **Resume Identity 强拒字段**（已在 ②.10/②.11）。换插件 → 强制重验。
- `VERIFY_SCHEMA` bump 条件 —— **仅判定规则语义变化**：
  - subject/issuer 匹配逻辑新增或改动（覆盖新 CA）
  - hybrid 的「TLS 无法确认才走 HTTP」短路策略本身变化
  - SNI 策略从「不发给发」且影响结果（实测封口后）
- **不 bump**：
  - 仅改插件*实现*（如 tls 自写改 pyOpenSSL）→ 只变 `verify_method` 字符串（仍强拒重验），不动 `VERIFY_SCHEMA`
  - **超时默认值调整**（仅默认参数，非协议）→ 不动 `VERIFY_SCHEMA`
  - SNI 阈值/开关微调（只要策略语义未变）
- `.cf.txt` 行格式变化才 bump `RESUME_SCHEMA`（已在 ②.9/②.10 定义）。

### ③.9 统计
- verify 本级：items/s（已处理/秒，含 PASS+FAIL+UNKNOWN）、PASS 率、UNKNOWN(探测失败)率、FAIL 率、各 `method`/`reason`/`confidence` 分布，实时显示（挂 ②.12 吞吐统计框架）。

### ③.10 架构定稿声明
- ③ 架构已定稿：职责、接口契约（③.2 `VerifyResult`）、短回路策略（③.3 hybrid）、Schema/Resume 映射（③.8）、统计（③.9）全部锁定。
- SNI 默认策略（③.5）与「subject O 作为最终主判据」（③.3）为**实现验证项，非架构问题**；最终通过真实环境验证微调，不影响架构、不 bump 任何 schema。
- `reason` 强制枚举（③.2 顶部 `REASON`）、`confidence` 证据强度已加，为未来 QUIC/ECH/API 插件贡献率分析预留，无需改接口。
- **④⑤⑥ 设计期间不得依赖 ③ 的 SNI 假设**：④ 做 ASN 归属、⑥ 用 extras 时，若读 `extras` 证书字段，须注明「其内容与 SNI 策略相关，非稳定判定输入」（见 ④.3 / ⑥ 注释）。

### ③.11 TLS 验证出口策略（实测+规模修正，推翻早期「默认代理」）
- **默认直连**（大规模扫描能跑）。理由：并发 5000~20000 时本地 SOCKS5 代理（Xray/V2Ray）承受不了几千并发 TCP 握手，会卡死崩溃。直连才是百万级扫描的可行出口。
- **代理仅小规模特殊环境用**：显式 `--proxy <addr:port>` 时走 SOCKS5（仅建议 <500 并发，如 WSL 下直连被墙的人工验证场景）。无 `--proxy` 则直连。
- 与 ⑤ 测速出口：⑤ 默认直连本地（测真实带宽），本就一致，无冲突。
- **证书验证默认开启**（推翻早期「默认关」误区）：`tls.Handshake()` 内对端证书链已自动解析进 `state.PeerCertificates`，读现成 `DNSNames` 遍历仅纳秒级零开销；且能在 HTTP 被拦截/403 时仍从四层确认是 CF（conf=low/high）。conf 分级：high(CF-RAY+证书) / mid(仅CF-RAY) / low(仅证书)。
- 历史注：早期曾拟「验证默认走代理」，被用户以高并发瓶颈纠正。

### ③ 未定点 / 待实测（未锁死）
1. ~~默认插件~~ → 已定 `hybrid`（tls+http 纯Python，短回路策略）。
2. ~~GTS 漏检表述~~ → 已改：TLS 无法明确时由 HTTP 行为特征补充判定，不绑定某 CA。
3. **SNI 默认策略（暂缓）**：待真实反代 IP 实测「发 SNI vs 不发 SNI」对比证书链+连接结果后再封口。
4. ~~TLS/ALPN 归属~~ → 已定：③ `decide()` 同一连接顺手采进 extras，不二次握手，PASS 落 `block_NNN.tls.txt`。
5. **超时**：无重试已定；超时值作为默认参数（2s/5s/5s），不锁进协议，不 bump schema。
6. ~~api 默认关~~ → 已定，仅显式开启。

#### ③ 封口前置实测（写码前一次性做）
- 拿 1~2 个真实「免费套餐 CF 反代 IP」样本：
  - 测 subject O 是否恒 "Cloudflare, Inc."（验证主信号）
  - 测 issuer 分布（确认 GTS/LE 等，佐证「不绑定 CA」）
  - **发 SNI vs 不发 SNI 各一次**，对比返回证书链与连接成败 → 决定 ③.5 默认策略
- 通过后用一次真实 IP 把 ③.3 主信号、③.5 SNI 默认 一次性钉死。

#### ③ 封口前置实测（与 ④⑤⑥ 统一真实验证一并做）
- 不每章停下测试；待 ④⑤⑥ 设计全定稿，统一用真实样本验证 ②③ 判定：
  - 测 subject O 是否恒 "Cloudflare, Inc."（验证主信号）
  - 测 issuer 分布（确认 GTS/LE 等，佐证「不绑定 CA」）
  - **发 SNI vs 不发 SNI 各一次**，对比返回证书链与连接成败 → 决定 ③.5 默认策略

## ④ enrich（定稿 v1）

### ④.1 职责边界
- ④ 在 ③ 阳性 IP:Port 集上，补充 **归属与地理元数据**：ASN + 国家 + 组织名。
- ④ **不重复判定 CF**：③ 已确认是 CF 端点；④ 只回答「这是谁的 ASN、在哪个国家」，供 ④.2 过滤 CF 官方自营、⑥ 报告展示。
- ④ **不采 TLS 版本/ALPN**（那是 ③.7 的 extras，④ 不用）。
- ④ **不测速**（留给 ⑤）。
- **架构铁律（原则 ⑨）**：④ 是增强模块不是判定模块。它可以补充信息、可过滤 CF 官方 ASN，但 **永远不能改变 ③ 的 Verify 结果，永远不能因查询失败丢弃 IP 或阻断 ⑤⑩ 后续流水线**。ASN/国家全查不到 → `ASN=-`/`Country=-`，IP 照常进 ⑤⑥。

### ④.2 过滤规则（仅过滤 CF 官方自营 ASN，清单外置）
- Cloudflare 官方 ASN 清单 **外置为可维护配置**（如 `config/cf_official_asns.txt`，一行一个 `AS13335`），不写死在代码里。以后 CF 新增 ASN 只改配置，不动代码、不 bump Schema。
- 默认清单（写码时核实官方最新公告）：`AS13335`(主) + `AS395747/AS132892/AS202623/AS133877/AS139242/AS203898/AS394536/AS400095/AS14789/...`（共 13 个，按需补）。
- 判定逻辑：**IP 的 ASN ∈ 清单 → 标记 `is_cf_official=True` 并剔除出最终优选集**（CF 自家边缘，非第三方反代）。
- **只过滤 CF 自身**：其他 ASN（含其他 CDN、云厂商、IDC、住宅宽带）一律保留，不过滤。
- 过滤结果写独立产物 `block_NNN.enrich.txt`，不回写 `.cf.txt`。

### ④.3 ASN 来源策略（Provider 抽象，不绑定主/备）
> **注意（呼应 ③.10）**：④ 读的是 **IP 所属 ASN**，与 ③ 的「证书 subject O」完全独立两层。④ 不得依赖 ③ 的 `extras` 证书字段做 ASN 判定（证书内容与 SNI 策略相关，非稳定输入）。

- **Provider 抽象**：`ENRICH_PROVIDERS: dict[str, EnrichProvider]`，每个 provider 实现 `query(ips) -> dict[ip, (asn,country,org)]`。当前实现为「本地库主源 + 在线兜底」：
  - `geolite2`（主）：MaxMind GeoLite2 本地 .mmdb（`GeoLite2-City` + `GeoLite2-ASN`），零限流、离线查询、多语言（含 zh-CN）。City 库给 `country/country_code/region_name/city/continent`，ASN 库给 `asn/org`（`autonomous_system_organization`，RIR 官方组织名，无需剥 `AS\d+` 前缀）。mmdb 文件放项目 `data/` 或 `~/.asnip/data/`（可用环境变量 `GEOLITE2_CITY`/`GEOLITE2_ASN` 指定路径）。
  - `ipapi`（兜底）：无 mmdb 时自动回退 `http://ip-api.com/batch`（≤100/批，走 `*_PROXY`），有限流 45 req/min 需礼貌间隔。**org 从 `as` 字段剥 `AS\d+ ` 前缀取**（ip-api 的 org 字段实测不可靠：会返回空/地名）；`country_cn/continent/flag` 由 `country_code` 查静态表（utils.py `COUNTRY_CN/COUNTRY_REGION/COUNTRY_FLAG`）派生。
  - ~~cymru~~：**已移除**（返回 RIR 注册国非地理国，实测确认）。
- **回退链**：`mmdb 可用 → geolite2`；否则 `ipapi`。缓存 `source` 记录实际来源；ip-api 缓存无 TTL 过期后失效重查。
- **单源同源**：country/region/city/大陆/国旗/中文名全部来自同一来源单次查询，杜绝多源口径不一致。
- **国家字段默认开**：本地库查询成本近零 → 默认 `--enrich-country` 开，`--no-enrich-country` 关。

### ④.4 缓存策略（永久缓存 + TTL + 失败回退）
- 每 IP 缓存：`cache/asn_{ip}.txt` = `asn|country|org|source|cached_at|country_code|region_name|city|country_cn|continent|flag`，**永久保留**。
- TTL 24h：超过 24h 用 GeoLite2 本地库刷新（本地查询近零成本）；**查询失败 → 直接用旧缓存**（不降级为 `ASN=-`）。离线能力强。
- 旧 `cymru`/`ipapi` 缓存因 `source != geolite2` 自动失效重查，无需手工清。
- `cached_at` 记录时间戳，报告/调试可见数据新鲜度。

### ④.5 输出 + source 溯源字段
- `block_NNN.enrich.txt` 每行：`IP:Port ASN COUNTRY ORG IS_CF_OFFICIAL SOURCE CACHED_AT`
  - `SOURCE` ∈ {`geolite2`, `cache`}：标注该行数据来自本地库 / 旧缓存。以后某 ASN 查错，一眼溯源，不用猜。
  - `CACHED_AT`：写入时间戳（ISO）。**（E 决议：不细分 `cache_fresh`/`cache_stale_fallback` 枚举）**——数据新鲜度直接看 `CACHED_AT` + ④.4 的 TTL 规则即可，增加 SOURCE 枚举只添复杂度、不增信息。
- 输入：③ 阳性 IP:Port（各 `block_NNN.cf.txt` 的 1 行）。
- 下游：作 ⑤ 测速对象 + ⑥ 报告富列。

### ④.6 并发与限速
- `geolite2`：本地 mmdb 查询，单进程内存映射读取，无网络、无限流；大批量也近实时完成。
- 断点：④ 按 block 落盘；单 IP 查询失败 → `ASN=-` 保留不丢（铁律 ⑨）。

### ④.7 与 Schema / Resume 映射
- ④ 产物 **不进 `scan_plan.json` Resume Identity**（元数据补充，非扫描/判定语义）。
- `OUTPUT_SCHEMA` 不进 Plan（已在 ②.11）。
- `ENRICH_SCHEMA`（占位=1）：当 `cf_official_asns` 清单文件格式变化、或 enrich.txt 行格式（如新增 SOURCE 列）变化时 bump（属《Schema Mapping》待固化项）。**注意**：清单*内容*增删只改配置、不 bump（原则 ⑨ + ④.2 外置）。
- ④ 失败 IP 不参与 Resume 强拒；重跑 ④ 即可补，无需重扫/重验。

### ④.8 统计
- enrich 本级：各 provider 命中率、cache 命中率、刷新失败回退旧缓存数、CF 官方 ASN 命中（将被过滤）数、items/s，实时显示（挂 ②.12 框架）。

---

### ④ 未定点（待拍板，未锁死）
1. **默认 provider 顺序**：当前 `cymru → ipapi` 回退链；最终默认值等统一实测后固化。
2. **cymru 礼貌并发 / ipapi 并发上限(32?)**：写码实测。
3. **ENRICH_SCHEMA 单列 vs 并入 OUTPUT_SCHEMA**：待《Schema Mapping》统一。
4. **国家默认开**：已定开（`--no-enrich-country` 关）。

## ⑤ speedtest（定稿 v1）

### ⑤.1 职责边界
- 对 ④ 输出中「**非 CF 官方自营**」的 IP:Port 测 **延迟（TCP+TLS 完整握手时间）+ 下载速度**。
- ⑤ 不判定 CF（③ 已做）、不查 ASN（④ 已做）；只产生速度维度的质量分。
- 测速是**质量排序**用途，非判定；失败/超时 IP 保留（标 `Latency=-`/`Download=0`），不剔除。
- **硬约束（F）**：⑤ 必须基于 **③ 已确认可用的连接上下文**进行测速——严格复用 ③ 探测时成功的 **Host / SNI / 端口**，禁止重新猜测 Host/SNI。理由：反代架构下 Host/SNI 决定 CF 边缘落到哪个路由/限速策略；若 ⑤ 与 ③ 用的 Host/SNI 不一致，两次测的就不是同一件事（边缘可能返回不同内容/限速档），数据不可比。
  - **⑤ 实现层已锁定的细则（用户拍板，非推测）**：
    1. **Range 精确取固定字节**（非限时读）：用 `Range: bytes=0-{N-1}` 精确取 `--speed-size` 字节。限时读法在网络抖动时「下载量」会变成延迟函数而非带宽函数，横向比较失真。
    2. **CF Challenge 页检测 → `DOWNLOAD=0`**：若 GET 返回 CF 质询页（`Just a moment...` 特征，或 `Content-Length` 未达 Range 要求字节数），判为「未取到真实数据流」，标 `DOWNLOAD=0`，**绝不硬塞一个虚假速度值**。
  - **留待 ⑤ 实现章节定的细节**：具体 GET 路径（`/` / `/cdn-cgi/trace` / `speed.cloudflare.com` 等）、非 HTTP（VMess/Trojan 隧道）的降级判定阈值。本设计阶段只锁「基于 ③ 已确认连接 + Range + Challenge 检测」原则。

### ⑤.2 直连与代理
- **强制直连**：`curl --noproxy '*'`（或纯 Python socket，见 ⑤.3），**不走系统代理**，与 ① 查 API 走代理相反（见 ① 坑A / ④.3 同类处理）。
- 本机在 GFW 下，第三方反代 IP 直连可能不稳/被墙——这是测速本身的网络限制，不影响 ③④ 判定结果，仅影响该 IP 的速度数据可信度。
- 可选 `--speed-proxy <addr>`：若用户想测「代理→IP」而非「本地→IP」（如本机直连不通），显式走代理测；默认直连。

### ⑤.3 测量方法（默认纯 Python socket 三步法）
- **默认方案 B（纯 Python socket 三步法，复用 IP 优选测速经验）**：TCP connect → TLS handshake → HTTP GET，全程本地计时，无外部依赖、跨平台稳定、易控并发。与项目「不依赖二进制」原则一致。
- 方案 A（curl 子进程 `--noproxy '*'`）作为备选；写码时实测两者精度差异，不影响默认选择。

### ⑤.4 延迟与下载口径（写码封口）
- **延迟**：对目标 IP:Port **连测 3 次取中位数**（非均值），避免单次抖动拉高结果。单点超时（默认 5s）→ 该次记为失败；3 次全失败 → `Latency=-`。
  - 延迟 = TCP 握手时间 + TLS 握手时间（含 TLS，贴近真实连接成本）。
- **下载速度**：发 `GET` 带 **`Range: bytes=0-{N-1}`** 精确取固定字节（默认 `N=--speed-size` 1MB），计实际收到时长算吞吐 `bytes/秒 → Mbps`；固定数据量便于不同 IP 横向比较「能拉多快」而非「测了多久」。
  - **CF Challenge 页检测（同 ⑤.1）**：若响应体是 CF 质询页（`Just a moment...`）或 `Content-Length` 未达 Range 要求字节数 → 判未取到真实数据流 → `Download=0`，不塞假速度。
  - 失败/超时 → `Download=0`。
- 方案 B 下：TCP+TLS 计时在握手阶段完成；下载阶段复用 ③ 已确认连接的 Host/SNI 发带 Range 的 GET，读满 N 字节或触发 Challenge 检测为止。

### ⑤.5 测全部 vs top N
- 默认**全测**（测速是纯本地 I/O，无外部 API 限流；④ 非官方集即便数千也仅受本机带宽约束）。
- 可选 `--speed-top N` 限制测速数量（如先按 ASN/端口聚类取 Top N）；默认不限制。

### ⑤.6 并发与限速
- 线程池（方案 B）：`--speed-workers`（默认礼貌值，写码实测本机带宽上限），建议 `min(CPU核×16, 128)` 量级起步。
- 背压/限速：单 IP 超时 `--speed-timeout`（默认 5s）+ 全局并发上限，避免本机出口拥塞导致数据失真。

### ⑤.7 产物
- `block_NNN.speed.txt`：每行 `IP:Port Latency_ms Download_Mbps`，独立产物，不回写 ③④。

### ⑤.8 与 Schema / Resume 映射
- 测速是性能测量，**不进 Resume Identity 强拒**（重跑 ⑤ 即可，无需重扫/重验/重 enrich）。
- `SPEED_SCHEMA`（占位 =1）：当延迟/速度定义变更或 `.speed.txt` 行格式变化时 bump（属《Schema Mapping》待固化项）。

### ⑤.9 统计
- speed 本级：已测/超时/失败数、平均延迟（中位数口径）、平均下载、items/s，实时显示（挂 ②.12 框架）。

---

### ⑤ 未定点（待拍板，未锁死）
1. **speed-workers 默认值 / speed-timeout 默认值**：写码实测本机带宽（默认建议 `min(CPU核×16, 128)`，超时 5s）。
2. **固定下载量 `--speed-size` 默认 1MB？** 还是 500KB/2MB 更合适？
3. **是否允许 --speed-proxy**：默认直连确认？
4. **延迟 3 次采样的单次超时**是否复用 `--speed-timeout`（5s）？确认。

## ⑥ output（定稿 v1）

### ⑥.1 职责边界
- ⑥ 是**报告层**：把 ③(cf.txt + tls.txt) / ④(enrich.txt) / ⑤(speed.txt) 各 block 产物按 `IP:Port` 主键 join，生成最终富列报告。
- ⑥ **不做任何判定/查询/测速**，纯合并 + 排序 + 格式化，可幂等重跑（重读中间产物即可，无需重扫/重验/重 enrich/重 speed）。
- **join 去重保险（H）**：按 `IP:Port` 去重，保留「有 ASN / 有速度」的更完整行（防多 block 边界/重跑产生的重复行）；不假设上游一定无重。
- **保持 Block 级流水线（J 决议）**：④ 全量完成才交 ⑤、⑤ 全量完成才交 ⑥，按 block 串行。**不新增 ④→⑤ 之间的阶段间流式管道**——已有 ②→③ 流水线，再加多级流式复杂度上升而收益有限。

### ⑥.2 报告列（默认 CSV）
```
IP | PORT | TLS | ALPN | Latency_ms | Download_Mbps | ASN | Country | Org | Is_CF_Official | Verify_Reason | Confidence
```
- `TLS` / `ALPN` 来自 ③ `block_NNN.tls.txt` 的 `extras`（注：SNI 相关、非稳定判定输入，仅展示见 ③.10）。
- `Latency_ms` / `Download_Mbps` 来自 ⑤ `.speed.txt`。
- `ASN` / `Country` / `Org` / `Is_CF_Official` 来自 ④ `.enrich.txt`。
- `Verify_Reason` / `Confidence` 来自 ③ `VerifyResult`（统计/排查用）。

### ⑥.3 输出格式与产物
- **默认 CSV**：`report.csv`（全字段），逗号分隔，首行表头。
- **JSON 输出（可选）**：`--json` 生成 `report.json`（同上字段，结构化，便于程序消费）。
- 默认只写 `report.csv`；`--json` 追加 `report.json`。
- **不直接写 KV / 不写 yxip_pool**：纯本地报告（设计基线 0 已定，保持独立工具定位）。

### ⑥.4 排序与过滤
- 默认排序（回答「哪个 IP 最快」）：**`Download_Mbps` 降序为主键 → `Latency_ms` 升序为次键**（`Latency=-` 沉底）。
- 先剔 `Is_CF_Official=True` 行（CF 官方非第三方反代），再排序。
- 可选 `--top N` 截断输出行数（不影响中间产物）。
- 默认**剔除** `Is_CF_Official=True` 行（第三方反代定位）；`--keep-cf-official` 可保留。

### ⑥.5 edgetunnel / 外部兼容
- **不强制兼容 edgetunnel 格式**（设计基线未要求；本工具独立报告）。
- 可选 `--export-edgetunnel` 生成 edgetunnel 订阅兼容子集（`IP:PORT` 列表 + 必要字段），作为未来扩展，不进默认。

### ⑥.6 与 Schema 映射
- `OUTPUT_SCHEMA`（占位 =1，已在 ② 定义）：报告列增删 / 格式语义变化时 bump。
- `OUTPUT_SCHEMA` **不进 Resume Identity**（②.11 已定），⑥ 重跑免费。

### ⑥.7 统计
- 合并行数、CF 官方剔除数、最终优选集大小，挂 ②.12 框架输出汇总。

---

### ⑥ 未定点（待拍板，未锁死）
1. **默认输出**：确认 CSV 默认 + 可选 `--json`？
2. **列集**：默认含 `Org` / `Verify_Reason` / `Confidence`？还是更精简？
3. **CF 官方默认剔除 + `--keep-cf-official` 保留**：已定确认。
4. **edgetunnel 导出**：是否要 `--export-edgetunnel`（默认不做）？
5. **排序默认键**：`Download_Mbps` 降序 + `Latency_ms` 升序，已定确认。

---

## 全阶段未定点汇总（待统一拍板 / 写码前实测）

### 架构已锁（无需再议）
- **①**：全部（含代理处理坑A、缓存 TTL 24h）
- **②**：全部（引擎骨架、Plan/调度分离、水位、原子写、IP:Port 级 Resume、强拒/软提示 meta）
- **③ 架构**：职责、VerifyResult 标准化（PASS/FAIL/UNKNOWN + reason 枚举 + confidence）、**hybrid 状态机（A：TLS PASS/FAIL 即收/拒，仅 UNKNOWN 才复连 http；http 永不推翻 TLS）**、**禁止重复 TLS 握手（B：http 复用 tls 已建 socket）**、SNI 缓议、超时退化默认参数、③.10 架构定稿声明
- **③.10 → 原则 ⑨**：Enrich 是增强模块不是判定模块（铁律）
- **④**：职责（不重判/不采TLS/不测速）、CF 官方 ASN 清单外置、**Provider 抽象（去主备）**、永久缓存+TTL+失败回退、**source 溯源 + cached_at（E 决议不细分 stale）**、国家默认开、cymru 批量 whois 优化项(C)、country=AS注册国非地理国注记(D)、不进 Resume、铁律 ⑨
- **⑤**：职责、强制直连、**硬约束（F：基于 ③ 已确认连接测速、禁重猜 Host/SNI；请求细节留待实现定）**、socket 三步法默认、延迟 3 次取中位数、下载固定 1MB、全测默认、不进 Resume
- **⑥**：报告层 join、**IP:Port 去重保险（H）**、CSV 默认+可选 json、**保持 Block 级流水线不新增 ④→⑤ 流式（J）**、列集方向、剔除 CF 官方、不写 KV、下载降序排序

### 待补章节（优先级：I 最前，因其反向耦合 ②③④⑤ checkpoint 语义）
- **⑦ Orchestrator + ⑧ Resource Guard（合并设计，优先级最高）**：
  - **用户决策（推翻前轮「I 延后」）**：I 应排在 A/B/F **最前面**。理由——电池护栏/暂停恢复语义会**反向耦合 ② 背压**的「暂停点在哪」假设；若先定 ②③④⑤ 接口、最后补 ⑦，可能发现骨架要求回头改前几步的 checkpoint/暂停接口。先定骨架，前几步接口预留对应钩子即可。
  - **⑦ Orchestrator**：顶层阶段链（①→②→③→④→⑤→⑥ 串接）、全局 CLI/配置加载、cache 根目录、全局参数分发、各阶段间「断点续跑钩子」标准化（与 ② IP:Port 级 Resume 对齐）。
  - **⑧ Resource Guard**：电池 ≤30% 停扫描、磁盘水位、退出信号（Ctrl-C / SIGTERM）的暂停-恢复语义；**必须与 ② 背压暂停复用同一套「暂停点在哪」语义**，避免两套暂停体系冲突。护栏触发时如何安全落盘中间产物、恢复后从哪续跑，需在设计 ② 时已预留。
  - **设计顺序**：先定 ⑦⑧ 的「暂停/恢复/断点」契约 → 回流确认 ②③④⑤ 各自 checkpoint 满足该契约 → 再细化 A/B/F 实现细则。

### 已锁定的 ③④⑤ 细则（本论拍板，非推测）
- **A/B（③ hybrid）**：见 ③.3 状态机 + 禁止重复 TLS 握手。
- **F（⑤ 连接复用 + 测速口径）**：见 ⑤.1 + ⑤.4 —— Host/SNI 复用 ③、Range 精确取字节、CF Challenge 页 → DOWNLOAD=0。

### 需拍板的设计未定点（纯默认参数，不阻塞）
- **④**：默认 provider 顺序（当前 `cymru→ipapi` 回退链）/ cymru 礼貌并发 / ipapi 并发上限(32?) / ENRICH_SCHEMA 单列否
- **⑤**：speed-workers 默认 / speed-timeout 默认 / `--speed-size` 默认 1MB? / 是否允许 --speed-proxy
- **⑥**：列集是否含 Org/Verify_Reason/Confidence / edgetunnel 导出是否做

### 需真实环境验证的实现项（统一做一次，不每章停）
1. ③ 主信号：真实样本 subject O 是否恒 "Cloudflare, Inc."
2. ③ issuer 分布（佐证不绑定 CA）
3. ③.5 SNI 默认策略：发 vs 不发，对比证书链 + 连接成败
4. ④ cymru/ipapi 各环境解析一致性 + 速率 + 礼貌并发值
5. ⑤ socket vs curl 测速精度对比（决定是否保留方案 A）
6. 全管线小样本端到端跑通（一个 ASN 子集）

### 样本来源（写码前实测用）
- FOFA 现有查询规则跑一批 → 挑 1~2 个「确认免费套餐（纯 Universal SSL、无企业证书特征）」IP
- 或找一个用 CF 免费版的小站点，对其解析 IP 实测（DV + Universal SSL 证书特征与扫描目标一致，足够验证 subject O 与 SNI 行为）

### Schema 占位清单（待《Schema Mapping》固化）
- `SCAN_SCHEMA=1` / `VERIFY_SCHEMA=1` / `RESUME_SCHEMA=1` / `OUTPUT_SCHEMA=1`（已有）
- 新增待固化：`ENRICH_SCHEMA=1`（④.7）/ `SPEED_SCHEMA=1`（⑤.8）

---

## 附录：未决/待实现时实测项
- ② 边解析边入队：到底用 `-oJ`（扫完写）还是 `-oL`（增量写），写码时实测 masscan 行为再定
- ⑤ 吞吐量显示格式，等 ④⑤⑥ 定了再定
- ④ ASN Provider 最终默认顺序 + 各环境解析一致性：写码前统一实测后固化（见全阶段汇总「需真实环境验证」第 4 项）
