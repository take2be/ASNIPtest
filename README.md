# ASNIPtest — 第三方 Cloudflare 反代 IP 优选工具

按 **ASN** 批量扫描并验证第三方 Cloudflare 反向代理节点，最终输出含延迟、下载速度、ASN、国家/地区信息的 CSV/JSON 报告。

## 核心特性

- 六阶段全自动管线：CIDR 获取 → masscan 端口发现 → cf-scanner 验证 → ASN 去官方 → 直连测速 → 导出报告
- **一键安装**：自动装系统依赖（Python/pip/masscan/cf-scanner）
- WSL / Linux / macOS 跨平台
- 断点续跑，Block 级 Resume
- 输出 CSV + JSON，自动启动 HTTP 下载服务

## 快速开始

### 系统要求

| 组件 | 最低要求 |
|------|---------|
| 系统 | Ubuntu 20.04+ / Debian 11+ / macOS / WSL2 |
| Python | 3.8+ |
| 权限 | root 或有 sudo 权限（装 masscan 用） |
| 硬件 | 2核+ / 512MB+ 内存 |
| 出口 | 公网带宽（masscan 与 cf-scanner 需要出站网络） |

### 一键安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh)
```

安装目录：`~/.asnip/`，命令：`asnip`

> WSL 下会提示是否需要走代理，Linux/VPS 默认直连。

### 一键卸载

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/uninstall.sh)
```

卸载会清理：安装目录 `~/.asnip` + `asnip` 命令 + 缓存。

## 使用

### 交互模式

```bash
asnip scan
```

流程：

1. 输入 ASN（例如：`13335,209554`）
2. 输入端口（回车默认：`443` `8443` `2053` `2083` `2087` `2096`）
3. WSL 下提示是否走代理；Linux 默认直连
4. 询问是否测速（测速较慢，默认跳过）

### 直接指定 ASN

```bash
asnip scan 400618
```

### 指定端口

```bash
asnip scan 13335 --ports 443,8443
```

### 强制刷新缓存

```bash
asnip scan 400618 --force
```

### 只输出前 N 个结果

```bash
asnip scan 400618 --top 20
```

### 跳过依赖检查

```bash
asnip scan 400618 --no-deps
```

### 后台运行（Linux VPS）

```bash
# 安装 screen（如未装）
apt update && apt install -y screen

# 开新窗口运行
screen -dmS asnip bash -c 'asnip scan 400618 > ~/asnip.log 2>&1'

# 查看日志
tail -f ~/asnip.log

# 回到窗口
screen -r asnip
```

## 输出

扫描完成后自动生成：

- `report.csv` — 主报告
- `report.json` — 结构化报告（加 `--json` 生成）

并启动 HTTP 服务，可直接下载：

```
http://<your-vps-ip>:8080/report.csv
http://<your-vps-ip>:8080/report.json
```

### CSV 字段说明

| 字段 | 说明 |
|------|------|
| ip_port | IP:Port |
| asn | 归属 ASN |
| country | 国家/地区 |
| org | 机构 |
| is_cf_official | 是否 Cloudflare 官方 ASN |
| latency_ms | 延迟 |
| download_mbps | 下载速度 |

## 管线说明

```
① ASN → CIDR        RIPEStat/BGPView，取 IPv4，去重，过滤不可扫网段
② masscan          全端口 SYN 扫描，发现开放端口
③ cf-scanner        TLS fingerprint，判断是否为 CF 反代
④ enrich            ip-api / cymru 补 ASN+国家，过滤 Cloudflare 官方 13 个 ASN
⑤ speedtest         TCP connect → TLS handshake → HTTP Range 下载测速
⑥ output           合并 enrich + speed，输出 CSV/JSON，启动 HTTP 服务
```

## 官方 CF ASN 过滤

以下 13 个 Cloudflare 官方 ASN 在 enrich 阶段自动剔除，不进入测速和输出：

- AS13335、AS395747、AS132892、AS202623、AS133877、AS139242
- AS203898、AS394536、AS400095、AS14789、AS209242、AS204829、AS200242

## 常见问题

### 如何更新到最新版？

```bash
rm -rf ~/.asnip
bash <(curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh)
```

### masscan 报错 Permission denied？

install.sh 会自动加 `cap_net_raw+ep`，无需 root 也能 raw socket。仍失败可手动：

```bash
sudo setcap cap_net_raw+ep $(which masscan)
```

### 测速很慢？

测速默认跳过。跑的时候选 `y` 才会测。

### 代理怎么设？

仅 WSL 环境需要。脚本会询问代理地址，默认 `127.0.0.1:10808`。

VPS/Linux 默认直连，不走代理。

### 支持 IPv6 吗？

当前版本只扫描 IPv4。IPv6 段在 CIDR 获取阶段已过滤。

## 贡献者

维护者：[take2be](https://github.com/take2be)  
原始作者：[e13815332](https://github.com/e13815332)

[![e13815332](https://github.com/e13815332.png?s=60)](https://github.com/e13815332)

## License

[MIT](LICENSE)
