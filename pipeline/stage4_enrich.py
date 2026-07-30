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

    返回: [{"ip_port", "asn", "country", "country_code", "region_name",
               "city", "org", "is_cf_official"}, ...]
    """
    ensure_dirs()
    cf_asns = load_cf_official_asns()
    results = []

    # 提取唯一 IP（去重）。rsplit 防 IPv6 被拆断
    _split = lambda ip_port: ip_port.rsplit(":", 1)[0]
    unique_ips = list({_split(ip_port) for ip_port in ip_ports if ":" in ip_port})

    # 查 IP 归属
    ip_info = _batch_lookup(unique_ips, proxies=proxies, on_progress=on_progress)

    for ip_port in ip_ports:
        ip = ip_port.rsplit(":", 1)[0] if ":" in ip_port else ip_port
        info = ip_info.get(ip, {
            "asn": "-", "country": "-", "country_code": "-",
            "region_name": "-", "city": "-", "org": "-",
            "cached_at": "-",
        })
        results.append({
            "ip_port": ip_port,
            "asn": info["asn"],
            "country": info["country"],
            "country_code": info.get("country_code", "-"),
            "region_name": info.get("region_name", "-"),
            "city": info.get("city", "-"),
            "org": info["org"],
            "is_cf_official": info["asn"] in cf_asns if isinstance(info["asn"], int) else False,
            "cached_at": info["cached_at"],
        })
        if on_progress:
            on_progress(len(results))

    return results


def _cache_valid(cached_at: str, ttl_seconds: int = 86400) -> bool:
    """检查缓存是否在 TTL 内（ASN 缓存 24h = 86400s）。"""
    if cached_at == "-":
        return False
    try:
        ts = time.mktime(time.strptime(cached_at, "%Y-%m-%dT%H:%M:%S"))
        return (time.time() - ts) < ttl_seconds
    except Exception:
        return False


def _batch_lookup(ips: list[str], proxies: dict | None = None,
                  on_progress=None) -> dict:
    """批量查 IP 归属。cymru -> ip-api 回退链。"""
    # 统一去掉可能的 :port，只保留纯 IP
    pure_ips = [ip.split(":")[0] if ":" in ip else ip for ip in ips]
    # 同时建立 pure_ip -> original_ip 的映射，方便 caller 对齐结果
    ip_map = {p: o for p, o in zip(pure_ips, ips)}

    result = {}

    # 先查缓存（24h TTL）
    uncached = []
    for ip in pure_ips:
        info = _read_cache(ip)
        if info and info.get("asn") != "-" and _cache_valid(info.get("cached_at", "-")):
            result[ip_map[ip]] = info
        else:
            uncached.append(ip)

    if not uncached:
        return result

    # cymru DNS 查询（批量）
    cymru_hits = _query_cymru_batch(uncached)
    for ip, info in cymru_hits.items():
        result[ip] = info
        _write_cache(ip, info)

    # cymru 只有 asn/org/country，缺 country_code/region_name/city。
    # 对 cymru 已命中的 IP，仍走 ip-api 补全缺失字段。
    needs_detail = [
        ip for ip in uncached
        if ip in result and any(result[ip].get(k) in (None, "-")
               for k in ("country_code", "region_name", "city"))
    ]
    if needs_detail:
        ipapi_hits = _query_ipapi_batch(needs_detail, proxies=proxies)
        for ip, info in ipapi_hits.items():
            merged = dict(result.get(ip, {}))
            merged.update({k: v for k, v in info.items()
                           if v not in (None, "-") and merged.get(k) in (None, "-")})
            result[ip] = merged
            _write_cache(ip, merged)

    # 仍未查到的标 -
    for ip in uncached:
        if ip not in result:
            info = {
                "asn": "-", "country": "-", "country_code": "-",
                "region_name": "-", "city": "-", "org": "-",
                "source": "-", "cached_at": "-",
            }
            result[ip] = info

    # 仍未查到的标 -（新字段也加）
    for ip in uncached:
        if ip not in result:
            info = {
                "asn": "-", "country": "-", "country_code": "-",
                "region_name": "-", "city": "-", "org": "-",
                "source": "-", "cached_at": "-",
            }
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
    """通过 ip-api.com batch API 查 IP 归属。

    返回: {ip: {asn, country, country_code, region, region_name,
                city, org, source, cached_at, timezone}}
    """
    if not ips:
        return {}

    result = {}
    # ip-api batch ≤ 100/次；取 country, regionName, city, countryCode 用于报告中文化/地区
    FIELDS = (
        "status,query,as,country,countryCode,region,regionName,"
        "city,org"
    )
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        url = f"http://ip-api.com/batch?fields={FIELDS}"
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
                    "country_code": entry.get("countryCode", "-"),
                    "region": entry.get("region", "-"),
                    "region_name": entry.get("regionName", "-"),
                    "city": entry.get("city", "-"),
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
            result = {
                "asn": int(parts[0]) if parts[0].isdigit() else parts[0],
                "country": parts[1],
                "org": parts[2],
                "source": parts[3],
                "cached_at": parts[4],
            }
            # 新字段（向后兼容旧缓存）
            if len(parts) >= 9:
                result["country_code"] = parts[5]
                result["region_name"] = parts[6]
                result["city"] = parts[7]
                # parts[8] 预留
            else:
                result["country_code"] = "-"
                result["region_name"] = "-"
                result["city"] = "-"
            return result
    except Exception:
        pass
    return None


def _write_cache(ip: str, info: dict):
    cache_file = os.path.join(CACHE_DIR, f"asn_{ip}.txt")
    with open(cache_file, "w") as f:
        f.write("|".join([
            str(info.get("asn", "-")),
            info.get("country", "-"),
            info.get("org", "-"),
            info.get("source", "-"),
            info.get("cached_at", "-"),
            info.get("country_code", "-"),
            info.get("region_name", "-"),
            info.get("city", "-"),
            "",  # 预留扩展位
        ]) + "\n")
