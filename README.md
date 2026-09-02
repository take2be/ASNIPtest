<div align="center">

# ASNIPtest

按 **ASN / IP 段** 批量扫描、验证第三方 Cloudflare 反代节点，输出含延迟、ASN、地区信息的 CSV 报告。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](#)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL2-lightgrey.svg)](#)

</div>

---

## 安装

```bash
curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh | bash
```

装到 `~/.asnip/`，命令注册到 `/usr/local/bin`，装完即用。

## 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/uninstall.sh | bash
```

清掉所有 `asnip-*` 会话（含僵尸）、安装目录、命令、缓存。

---

## 命令总览

| 命令 | 作用 |
|---|---|
| `irds <ASN>` | 扫描，screen 后台 + 进度界面 |
| `irds <ASN1>,<ASN2>` | 一次扫多个 ASN（复合会话 `asnip-<asn1>-multi`） |
| `irds` | 交互管理菜单 |
| `irds -ls` | 列出会话 |
| `irds -stop <ASN>` | 停某 ASN 相关会话（含复合） |
| `irds -stop-all` | 停全部会话 |
| `irds-result` | 查看最近结果（前 10 条） |
| `irds -version` | 核对已装版本与 GitHub 最新版 |
| `irds -panel` | 面板与结果下载的说明 |
| `irds-http` | 结果下载服务（8081，需 attach） |
| `irds-progress` | 进度面板（8082，前台运行带令牌） |
| `ips <ASN>` | 前台直接跑（不用 screen） |

---

## 使用

### 开始扫描

扫描单个：

```bash
irds <ASN>
```

一次扫多个 ASN：

```bash
irds <ASN1>,<ASN2>
```

直接扫 IP 段（不用 ASN，跳过 RIPEStat/BGPView 拉取）：

```bash
irds <IP段>
irds <IP段1>,<IP段2>
```

> IP 段与 ASN 只能二选一（不支持混合）；`irds` 复用 screen 后台、`ips` 复用前台单次，逻辑不变。

指定端口：

```bash
irds <ASN> --ports 443,8443
```

指定速率（不指则交互询问，默认 2000）：

```bash
irds <ASN> --rate 5000
```

忽略缓存强制刷新：

```bash
irds <ASN> --force
```

只输出前 N 个结果：

```bash
irds <ASN> --top 20
```

不用 screen（不要后台/续跑）：

```bash
ips <ASN>
```

> 交互依次问：ASN、端口、是否测速、扫描速率，速率设多少跑多少。

### 会话管理

| 操作 | 输入 |
|---|---|
| 退出界面（任务继续跑） | `Ctrl+A` `D` |
| 重进界面 | `irds <ASN>` 或 `screen -r asnip-<ASN>` |
| 中断任务 | `Ctrl+C` |
| 杀会话 | `Ctrl+A` `K` → `y` |
| 停某 ASN | `irds -stop <ASN>` |
| 停全部 | `irds -stop-all` |

### 查看结果

```bash
irds-result
```

结果文件 `output_{ASN}_{时间戳}.csv`，只留最近 2 个。

### 网页面板与下载

面板（8082）和结果下载（8081）只在 attach 进扫描会话时开放，detach 后端口立即关闭。attach 后终端会打印当次的访问链接，链接自带一次性令牌，重新 attach 会换新的。

```bash
irds <ASN>        # 启动扫描或接回已有会话，attach 后显示链接
irds -panel       # 面板与下载的说明
```

不带令牌访问一律 401。服务只放行面板接口和 `output_*.csv|json`，其他路径全部 404，不会暴露源码和本地数据库。

---

## CSV 字段

`IP地址` `端口号` `TLS` `IP位置` `地区` `城市` `大陆` `国家(中文)` `国旗` `网络延迟(ms)` `ASN号码` `ASN组织` `访问协议` `测速`

延迟必测，测速可选。延迟 = TCP+TLS 握手，测速 = HTTP Range 下载速度。

---

## 管线

| 阶段 | 说明 |
|---|---|
| 1/6 ASN→CIDR | RIPEStat/BGPView，取 IPv4，过滤不可扫网段 |
| 2-3/6 masscan + verify | 50 段 mini-block，扫出即验，流式缓存 |
| 4/6 enrich | GeoLite2 补 ASN+地区+大陆，剔除 CF 官方 ASN |
| 5/6 speedtest | 延迟必测，测速可选 |
| 6/6 output | 合并、导出 CSV、起 HTTP 服务 |

自动剔除的 CF 官方 ASN：

```
AS13335 AS395747 AS132892 AS202623 AS133877 AS139242
AS203898 AS394536 AS400095 AS14789 AS209242 AS204829 AS200242
```

---

## 常见问题

**更新**：重跑 install.sh 覆盖安装。

**Permission denied**：

```bash
sudo setcap cap_net_raw+ep $(which masscan)
```

**代理**：仅 WSL 需要，首次运行会问，默认 `127.0.0.1:10808`，Linux/VPS 直连。

**IP 归属数据**：enrich 用 GeoLite2 本地库，离线无限流；没装则用 ip-api 在线查。两者都免费。

想用 GeoLite2，指定环境变量 `MM_LICENSE_KEY` 再装：

```bash
MM_LICENSE_KEY=你的key bash -c "$(curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh)"
```

key 去 <https://www.maxmind.com/en/geolite2/signup> 注册，再到 <https://www.maxmind.com/en/accounts/current/license-key> 生成。不填也能用，enrich 走 ip-api。

**IPv6**：暂不支持，只扫 IPv4。

---

## License

[MIT](LICENSE)
