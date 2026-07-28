"""④ enrich — ASN/国家/组织查询 + CF 官方 ASN 过滤

Provider 抽象（cymru DNS + ip-api batch），可回退。
遵守铁律：查询失败不丢 IP，ASN=-/Country=- 继续流水线。
"""

import os
import sys
import time
import re
import socket
import urllib.request
import urllib.error
import json
import threading
from pathlib import Path

from .utils import log, CACHE_DIR, CONFIG_DIR, atomic_write, sha256_text, RateCounter

# ── 常量 ──────────────────────────────────────────────────────────────
IPAPI_BATCH_URL = "http://ip-api.com/batch"
IPAPI_FIELDS = "query,as,country,org,asname"
CACHE_TTL = 86400  # 24h
ENRICH_SCHEMA = 1


def _parse_asn_cidr(ip: str) -> str | None:
    """DNS 查 cymru: AS{ip}.origin.asn.cymru.com → ASN|网段|国家"""
    try:
        rev = ".".join(reversed(ip.split(".")))
        name = f"{rev}.origin.asn.cymru.com"
        answers = socket.getaddrinfo(name, 0, socket.AF_INET, socket.SOCK_STREAM)
        # 实际用 DNS TXT 记录
        result = socket.gethostbyname_ex(name)
        # cymru 返回 TXT 格式 "ASN | CIDR | Country | Org"
        # 但 gethostbyname_ex 只返回 A 记录，需要用 dnspython
        return None
    except Exception:
        return None


def _query_cymru_txt(ip: str) -> dict | None:
    """用 dnspython 查 cymru TXT 记录

    Returns: {"asn": "AS13335", "country": "US", "org": "Cloudflare"} or None
    """
    try:
        import dns.resolver
        rev = ".".join(reversed(ip.split(".")))
        name = f"{rev}.origin.asn.cymru.com"
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        for answer in answers:
            txt = answer.to_text().strip('"')
            parts = [p.strip() for p in txt.split("|")]
            if len(parts) >= 3:
                asn = parts[0].strip()
                # cymru ASN 格式可能是 "13335" 或 "AS13335"
                if not asn.startswith("AS"):
                    asn = "AS" + asn
                return {
                    "asn": asn,
                    "country": parts[2].strip(),
                    "org": parts[3].strip() if len(parts) > 3 else "",
                    "source": "cymru",
                }
    except ImportError:
        # dnspython 未安装
        return None
    except Exception:
        return None
    return None


def _query_ipapi_batch(ips: list[str]) -> dict[str, dict]:
    """批量查 ip-api.com （≤100/批）

    Args:
        ips: IP 地址列表

    Returns: {ip: {asn, country, org, source}}
    """
    if not ips:
        return {}

    result = {}
    # 分批次 ≤100
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        data = json.dumps(batch).encode()
        req = urllib.request.Request(
            IPAPI_BATCH_URL + "?fields=" + IPAPI_FIELDS,
            data=data,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                rows = json.loads(resp.read().decode())
            for row in rows:
                ip = row.get("query", "")
                if not ip:
                    continue
                as_str = row.get("as", "")
                asn = ""
                if as_str:
                    # 格式 "AS13335 Cloudflare"
                    parts = as_str.split(" ", 1)
                    asn = parts[0] if parts[0].startswith("AS") else ""
                    org = parts[1] if len(parts) > 1 else ""
                result[ip] = {
                    "asn": asn,
                    "country": row.get("country", ""),
                    "org": org or row.get("org", ""),
                    "source": "ipapi",
                }
        except Exception as e:
            log.warning(f"  ⚠️ ip-api 批次查询失败 ({len(batch)} IPs): {e}")
            # 失败不丢 IP，全标空
            for ip in batch:
                result[ip] = {"asn": "", "country": "", "org": "", "source": "ipapi_fail"}

        # ip-api 免费限速 45 req/min
        if i + 100 < len(ips):
            time.sleep(1.5)

    return result


def _load_cf_official_asns() -> set[str]:
    """加载 CF 官方 ASN 清单"""
    asns = set()
    path = CONFIG_DIR / "cf_official_asns.txt"
    if path.exists():
        for line in path.read_text().strip().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                asns.add(line.upper())
    return asns


def _cache_path(ip: str) -> Path:
    return CACHE_DIR / f"asn_{ip}.txt"


def _read_cache(ip: str) -> dict | None:
    """读 ASN 缓存（过期返回 None 但内容保留作回退）"""
    path = _cache_path(ip)
    if not path.exists():
        return None
    try:
        data = path.read_text().strip().split("|")
        if len(data) >= 5:
            age = time.time() - float(data[4])
            return {
                "asn": data[0],
                "country": data[1],
                "org": data[2],
                "source": data[3],
                "cached_at": float(data[4]),
                "fresh": age < CACHE_TTL,
            }
    except Exception:
        pass
    return None


def _write_cache(ip: str, info: dict):
    """写 ASN 缓存"""
    content = f"{info['asn']}|{info['country']}|{info['org']}|{info['source']}|{time.time()}"
    atomic_write(str(_cache_path(ip)), content)


def enrich_ips(
    ip_port_list: list[str],
    use_proxy: bool = True,
    force: bool = False,
) -> dict[str, dict]:
    """批量 enrich IP:Port 列表

    Args:
        ip_port_list: ["ip:port", ...]
        use_proxy: 是否尊重系统代理（ip-api 走 HTTP）
        force: 是否跳过缓存

    Returns:
        {ip_port: {"asn": str, "country": str, "org": str, "is_cf_official": bool, "source": str}}
    """
    # 提取唯一 IP
    unique_ips = sorted(set(ip_port.split(":", 1)[0] for ip_port in ip_port_list))

    # 加载 CF 官方 ASN 清单
    cf_asns = _load_cf_official_asns()
    log.info(f"  📋 CF 官方 ASN 清单: {len(cf_asns)} 个")

    # 尝试读取缓存
    need_online: list[str] = []
    cache_results: dict[str, dict] = {}

    for ip in unique_ips:
        cached = _read_cache(ip)
        if cached and (cached["fresh"] or force):
            cache_results[ip] = cached
        else:
            need_online.append(ip)

    log.info(f"  💾 缓存命中: {len(cache_results)}/{len(unique_ips)}")

    # 在线查询
    online_results: dict[str, dict] = {}

    if need_online:
        # cymru DNS 优先（纯 DN，无需代理）
        cymru_batch: list[str] = []
        ipapi_batch: list[str] = []

        for ip in need_online:
            result = _query_cymru_txt(ip)
            if result:
                online_results[ip] = result
                _write_cache(ip, result)
            else:
                ipapi_batch.append(ip)

        log.info(f"  🌐 cymru: {len(online_results)} / {len(need_online)}")

        # ip-api 补漏（走代理）
        if ipapi_batch:
            log.info(f"  🌐 ip-api 补漏: {len(ipapi_batch)} IPs...")
            batch_results = _query_ipapi_batch(ipapi_batch)
            for ip, info in batch_results.items():
                if info["asn"] or info["source"] != "ipapi_fail":
                    online_results[ip] = info
                    _write_cache(ip, info)
                else:
                    # ip-api 也失败 → 空数据，仍写缓存（防重复查）
                    empty = {"asn": "", "country": "", "org": "", "source": "ipapi_fail"}
                    online_results[ip] = empty
                    _write_cache(ip, empty)

    # 合并结果
    all_info: dict[str, dict] = {}
    all_info.update(cache_results)
    all_info.update(online_results)

    # 组装回 IP:Port 列表
    result: dict[str, dict] = {}
    for ip_port in ip_port_list:
        ip = ip_port.split(":", 1)[0]
        info = all_info.get(ip, {"asn": "", "country": "", "org": "", "source": ""})
        asn = info.get("asn", "")
        is_cf = asn.upper() in cf_asns
        result[ip_port] = {
            "asn": asn,
            "country": info.get("country", ""),
            "org": info.get("org", ""),
            "is_cf_official": is_cf,
            "source": info.get("source", ""),
        }

    # 统计
    found = sum(1 for v in result.values() if v["asn"])
    cf_hits = sum(1 for v in result.values() if v["is_cf_official"])
    log.info(f"  📊 enrich: {len(result)} IPs, ASN 查到 {found}, CF 官方 {cf_hits}")

    return result


def write_enrich_file(
    enrich_data: dict[str, dict],
    output_path: str,
):
    """写 block_NNN.enrich.txt

    格式: IP:Port ASN COUNTRY ORG IS_CF_OFFICIAL SOURCE CACHED_AT
    """
    lines = []
    for ip_port, info in sorted(enrich_data.items()):
        lines.append(
            f"{ip_port} {info['asn']} {info['country']} {info['org']} "
            f"{int(info['is_cf_official'])} {info['source']}"
        )
    atomic_write(output_path, "\n".join(lines) + "\n")
    log.info(f"  📄 {os.path.basename(output_path)}: {len(lines)} 行")


# ── 独立测试 ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_ips = ["1.1.1.1", "8.8.8.8", "185.92.220.1"]
    result = enrich_ips(test_ips)
    for ip, info in result.items():
        print(f"  {ip}: ASN={info['asn']} Country={info['country']} CF={info['is_cf_official']}")
