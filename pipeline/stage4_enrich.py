"""④ enrich：为已验证 IP 补充 ASN+国家+组织信息。

Provider 链：cymru (DNS) → ip-api (HTTP batch)
铁律：查询失败不丢 IP，标记 ASN=- / Country=-
"""
import json
import os
import socket
import time
import urllib.error
import urllib.request

from .utils import load_cf_official_asns, ensure_dirs, CACHE_DIR


def enrich_ips(ip_ports: list[str], proxies: dict | None = None,
               on_progress=None) -> list[dict]:
    """对 IP:Port 列表补充 ASN/国家/组织。

    返回: [{"ip_port", "asn", "country", "org", "is_cf_official", "source", "cached_at"}, ...]
    """
    ensure_dirs()
    cf_asns = load_cf_official_asns()
    results = []

    # 提取唯一 IP（去重）
    unique_ips = list({ip_port.split(":")[0] for ip_port in ip_ports if ":" in ip_port})

    # 查 IP 归属
    ip_info = _batch_lookup(unique_ips, proxies=proxies, on_progress=on_progress)

    for ip_port in ip_ports:
        ip = ip_port.split(":")[0]
        info = ip_info.get(ip, {"asn": "-", "country": "-", "org": "-",
                                "source": "-", "cached_at": "-"})
        results.append({
            "ip_port": ip_port,
            "asn": info["asn"],
            "country": info["country"],
            "org": info["org"],
            "is_cf_official": info["asn"] in cf_asns if isinstance(info["asn"], int) else False,
            "source": info["source"],
            "cached_at": info["cached_at"],
        })
        if on_progress:
            on_progress(len(results))

    return results


def _batch_lookup(ips: list[str], proxies: dict | None = None,
                  on_progress=None) -> dict:
    """批量查 IP 归属。cymru -> ip-api 回退链。"""
    result = {}

    # 先查缓存
    uncached = []
    for ip in ips:
        info = _read_cache(ip)
        if info and info.get("asn") != "-":
            result[ip] = info
        else:
            uncached.append(ip)

    if not uncached:
        return result

    # cymru DNS 查询（批量）
    cymru_hits = _query_cymru_batch(uncached)
    for ip, info in cymru_hits.items():
        result[ip] = info
        _write_cache(ip, info)

    # 仍未查到 或 缺 org 的用 ip-api 补
    still_missing = [
        ip for ip in uncached
        if ip not in result or result[ip].get("org", "-") == "-"
    ]
    if still_missing:
        ipapi_hits = _query_ipapi_batch(still_missing, proxies=proxies)
        for ip, info in ipapi_hits.items():
            result[ip] = info
            _write_cache(ip, info)

    # 仍未查到的标 -
    for ip in uncached:
        if ip not in result:
            info = {"asn": "-", "country": "-", "org": "-",
                    "source": "-", "cached_at": "-"}
            result[ip] = info

    return result


def _query_cymru_batch(ips: list[str]) -> dict:
    """通过 cymru.com DNS TXT 查 ASN（批量）。"""
    result = {}
    # Team Cymru 的 origin.asn.cymru.com DNS 查询
    for ip in ips:
        try:
            rev_ip = ".".join(reversed(ip.split(".")))
            query = f"{rev_ip}.origin.asn.cymru.com"
            answers = socket.getaddrinfo(query, 0, socket.AF_INET, socket.SOCK_DGRAM)
            # 实际需要 DNS TXT 记录，Python 标准库不直接支持
            # 用 dnspython 或 socket 协议查
            import dns.resolver
            try:
                resp = dns.resolver.resolve(query, "TXT", lifetime=5)
                txt = " ".join(r.to_text() for r in resp)
                # 格式: "ASN | Prefix | Country | Registry | Allocated | Org"
                parts = txt.strip('"').split(" | ")
                asn = int(parts[0]) if parts[0].isdigit() else "-"
                country = parts[2] if len(parts) > 2 else "-"
                org = parts[5] if len(parts) > 5 else "-"
                result[ip] = {
                    "asn": asn,
                    "country": country,
                    "org": org,
                    "source": "cymru",
                    "cached_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                }
            except Exception:
                continue
        except Exception:
            continue
    return result


def _query_ipapi_batch(ips: list[str], proxies: dict | None = None) -> dict:
    """通过 ip-api.com batch API 查 IP 归属。"""
    if not ips:
        return {}

    result = {}
    # ip-api batch 限制 100 IP/次
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        url = "http://ip-api.com/batch"
        data = json.dumps(batch).encode()

        try:
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"}
            )
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler(proxies or {})
            )
            with opener.open(req, timeout=15) as resp:
                entries = json.loads(resp.read())

            for entry in entries:
                ip = entry.get("query", "")
                if not ip:
                    continue
                asn_str = entry.get("as", "")
                asn_match = __import__("re").search(r"AS(\d+)", asn_str)
                asn = int(asn_match.group(1)) if asn_match else "-"
                result[ip] = {
                    "asn": asn,
                    "country": entry.get("country", "-"),
                    "org": entry.get("org", "-"),
                    "source": "ipapi",
                    "cached_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                }
        except Exception as e:
            print(f"  ⚠ ip-api batch 失败 ({len(batch)} IP): {e}")

    return result


def _read_cache(ip: str) -> dict | None:
    cache_file = os.path.join(CACHE_DIR, f"asn_{ip}.txt")
    if not os.path.exists(cache_file):
        return None
    try:
        with open(cache_file) as f:
            parts = f.read().strip().split("|")
            if len(parts) >= 5:
                return {
                    "asn": int(parts[0]) if parts[0].isdigit() else parts[0],
                    "country": parts[1],
                    "org": parts[2],
                    "source": parts[3],
                    "cached_at": parts[4],
                }
    except Exception:
        pass
    return None


def _write_cache(ip: str, info: dict):
    cache_file = os.path.join(CACHE_DIR, f"asn_{ip}.txt")
    with open(cache_file, "w") as f:
        f.write(f"{info['asn']}|{info['country']}|{info['org']}|{info['source']}|{info['cached_at']}\n")
