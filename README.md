# ASNIPtest — 第三方 Cloudflare 反代 IP 优选工具

按 **ASN** 批量扫描并验证第三方 Cloudflare 反向代理节点，最终输出含延迟、下载速度、ASN、国家/地区信息的 CSV/JSON 报告。

## 核心特性

- 六阶段全自动管线：CIDR 获取 → masscan 端口发现 → cf-scanner 验证 → ASN 去官方 → 直连测速 → 导出报告
- **一键安装**：自动装系统依赖（Python/pip/masscan/cf-scanner）
- WSL / Linux / macOS 跨平台
- 50 段 mini-block 流水线，断点续跑，IP:PORT 流式缓存
- `irds <ASN>` 一键守护扫描，SSH 断线自动续跑，直到出报告
- `irds-result` 直接查看最近一次可用 IP 汇总
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
curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh | bash
source ~/.bashrc
```

安装目录：`~/.asnip/`，命令：`asnip` / `ips` / `irds` / `irds-result`

> Linux/VPS 默认直连。WSL 下首次运行会提示是否需要走代理。

### 一键卸载

```bash
curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/uninstall.sh | bash
```

卸载会清理：安装目录 `~/.asnip` + 命令 + 缓存。

## 使用

### 推荐：自动续跑守护模式

```bash
irds <ASN>
```

或任意 ASN：

```bash
irds 13335,209554
irds 209554,13335
```

`irds` 会在后台循环运行，直到生成完整报告为止。SSH 断线后也会自动续跑。

查看结果：

```bash
irds-result
```

### 直接指定 ASN（单次）

```bash
asnip scan <ASN>
# 或快捷命令
ips <ASN>
```

### 指定端口

```bash
irds 13335,209554 --ports 443,8443
```

### 强制刷新缓存

```bash
irds <ASN> --force
```

### 只输出前 N 个结果

```bash
irds <ASN> --top 20
```

### 跳过测速

默认跳过测速，想要测速在交互模式下选 `y`，或：

```bash
asnip scan 400618
# 或快捷命令
ips 400618
```

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
1/6 ASN → CIDR        RIPEStat/BGPView，取 IPv4，去重，过滤不可扫网段
2/6 masscan + 3/6 verify  50 段 mini-block 流水线，扫出即验，流式缓存 IP:PORT
4/6 enrich            ip-api / cymru 补 ASN+国家，过滤 Cloudflare 官方 13 个 ASN
5/6 speedtest         TCP connect → TLS handshake → HTTP Range 下载测速
6/6 output           合并 enrich + speed，输出 CSV/JSON，启动 HTTP 服务
```

## 官方 CF ASN 过滤

以下 13 个 Cloudflare 官方 ASN 在 enrich 阶段自动剔除，不进入测速和输出：

- AS13335、AS395747、AS132892、AS202623、AS133877、AS139242
- AS203898、AS394536、AS400095、AS14789、AS209242、AS204829、AS200242

## 常见问题

### 如何更新到最新版？

```bash
rm -rf ~/.asnip
curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh | bash
source ~/.bashrc
```

### masscan 报错 Permission denied？

install.sh 会自动加 `cap_net_raw+ep`，无需 root 也能 raw socket。仍失败可手动：

```bash
sudo setcap cap_net_raw+ep $(which masscan)
```

### 测速很慢？

测速默认跳过。跑的时候选 `y` 才会测。

### 代理怎么设？

仅 WSL 环境需要。首次运行脚本会询问代理地址，默认 `127.0.0.1:10808`。

VPS/Linux 默认直连，不走代理。

### 支持 IPv6 吗？

当前版本只扫描 IPv4。IPv6 段在 CIDR 获取阶段已过滤。

## 贡献者

维护者：[take2be](https://github.com/take2be)
原始作者：[e13815332](https://github.com/e13815332)

[![e13815332](https://github.com/e13815332.png?s=60)](https://github.com/e13815332)

## License

[MIT](LICENSE)
