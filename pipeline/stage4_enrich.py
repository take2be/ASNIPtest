"""④ enrich：为已验证 IP 补充 ASN+国家+组织+大陆信息。

数据源（按可用性回退）：
  主：MaxMind GeoLite2 本地库（GeoLite2-City + GeoLite2-ASN，离线、多语言、零限流）
  兜底：ip-api.com（无 mmdb 时用，在线、有免费限流；org 从 as 字段解析，
        country_cn/continent/flag 由静态表派生）
铁律：查询失败不丢 IP，标记 ASN=- / Country=-
"""
import os
import time

from .utils import (
    load_cf_official_asns, ensure_dirs, CACHE_DIR,
    COUNTRY_CN, COUNTRY_REGION, COUNTRY_FLAG,
)

# GeoLite2 mmdb 文件所在目录（探测优先级：环境变量 > 项目 data/ > ~/.asnip/data）
_MMDB_BASES = [
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"),
    os.path.expanduser("~/.asnip/data"),
    "data",
]


def _mmdb_path(name: str) -> str:
    """定位 mmdb 文件。env: GEOLITE2_CITY / GEOLITE2_ASN 可显式指定。"""
    env = os.environ.get(f"GEOLITE2_{name.upper()}", "")
    if env and os.path.exists(env):
        return env
    for base in _MMDB_BASES:
        p = os.path.join(base, f"{name}.mmdb")
        if os.path.exists(p):
            return p
    return os.path.join(_MMDB_BASES[0], f"{name}.mmdb")


def mmdb_available() -> bool:
    """两个 mmdb 都就绪才算主源可用。"""
    return os.path.exists(_mmdb_path("GeoLite2-City")) and \
           os.path.exists(_mmdb_path("GeoLite2-ASN"))


def _country_code_to_flag(cc: str) -> str:
    """ISO 3166-1 alpha-2 国家码 → 国旗 emoji（Unicode 区域指示符算法，零依赖）。"""
    if not cc or len(cc) != 2:
        return ""
    return "".join(chr(ord(c) - ord("A") + 0x1F1E6) for c in cc.upper())


class _GeoLite2:
    """懒加载 GeoLite2-City / GeoLite2-ASN 两个本地库。文件缺失/损坏时标记失败，不崩主流程。"""

    def __init__(self):
        self._city = None
        self._asn = None
        self._city_err = None
        self._asn_err = None

    def _open_city(self):
        if self._city is None and self._city_err is None:
            try:
                import maxminddb
                self._city = maxminddb.open_database(_mmdb_path("GeoLite2-City"))
            except Exception as e:
                self._city_err = e
        return self._city

    def _open_asn(self):
        if self._asn is None and self._asn_err is None:
            try:
                import maxminddb
                self._asn = maxminddb.open_database(_mmdb_path("GeoLite2-ASN"))
            except Exception as e:
                self._asn_err = e
        return self._asn

    def lookup(self, ip: str) -> dict:
        """单 IP 查询，返回 GeoLite2 同源全部字段。任一库缺失该 IP 时该字段标 '-'。"""
        info = {
            "asn": "-", "org": "-",
            "country": "-", "country_code": "-", "country_cn": "-",
            "region_name": "-", "city": "-", "continent": "-",
            "flag": "-",
        }
        city = self._open_city()
        if city is not None:
            try:
                rec = city.get(ip)
                if rec:
                    country = rec.get("country") or {}
                    continent = rec.get("continent") or {}
                    names = country.get("names") or {}
                    info["country"] = names.get("en", "-")
                    info["country_code"] = country.get("iso_code", "-")
                    info["country_cn"] = names.get("zh-CN", info["country"])
                    info["continent"] = (continent.get("names") or {}).get("zh-CN", "-")
                    subs = rec.get("subdivisions") or []
                    if subs:
                        info["region_name"] = (subs[0].get("names") or {}).get("en", "-")
                    city_rec = rec.get("city") or {}
                    info["city"] = (city_rec.get("names") or {}).get("en", "-")
            except Exception:
                pass

        asn = self._open_asn()
        if asn is not None:
            try:
                rec = asn.get(ip)
                if rec:
                    info["asn"] = rec.get("autonomous_system_number", "-")
                    info["org"] = rec.get("autonomous_system_organization", "-")
            except Exception:
                pass

        info["flag"] = _country_code_to_flag(info["country_code"]) or "-"
        return info


# 单例（进程内只开一次 mmdb 句柄）
_GEOLITE2 = _GeoLite2()


def enrich_ips(ip_ports: list[str], proxies: dict | None = None,
               on_progress=None) -> list[dict]:
    """对 IP:Port 列表补充 ASN/国家/组织/大陆。

    返回: [{"ip_port", "asn", "country", "country_code", "country_cn",
               "region_name", "city", "continent", "flag", "org",
               "is_cf_official"}, ...]
    """
    ensure_dirs()
    cf_asns = load_cf_official_asns()
    results = []

    # 提取唯一 IP（去重）。rsplit 防 IPv6 被拆断
    _split = lambda ip_port: ip_port.rsplit(":", 1)[0]
    unique_ips = list({_split(ip_port) for ip_port in ip_ports if ":" in ip_port})

    # 查 IP 归属（GeoLite2 主源 + ip-api 兜底）
    ip_info = _batch_lookup(unique_ips, proxies=proxies, on_progress=on_progress)

    for ip_port in ip_ports:
        ip = ip_port.rsplit(":", 1)[0] if ":" in ip_port else ip_port
        info = ip_info.get(ip, {
            "asn": "-", "country": "-", "country_code": "-", "country_cn": "-",
            "region_name": "-", "city": "-", "continent": "-", "flag": "-",
            "org": "-", "cached_at": "-",
        })
        results.append({
            "ip_port": ip_port,
            "asn": info["asn"],
            "country": info["country"],
            "country_code": info.get("country_code", "-"),
            "country_cn": info.get("country_cn", "-"),
            "region_name": info.get("region_name", "-"),
            "city": info.get("city", "-"),
            "continent": info.get("continent", "-"),
            "flag": info.get("flag", "-"),
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
    """批量查 IP 归属。mmdb 就绪走 GeoLite2 本地库，否则 ip-api 兜底。"""
    # 统一去掉可能的 :port，只保留纯 IP
    pure_ips = [ip.split(":")[0] if ":" in ip else ip for ip in ips]
    ip_map = {p: o for p, o in zip(pure_ips, ips)}

    result = {}

    # 先查缓存（24h TTL，且必须 source∈{geolite2,ipapi}；旧 cymru 视为失效）
    uncached = []
    for ip in pure_ips:
        info = _read_cache(ip)
        if info and info.get("asn") != "-" and info.get("source") in ("geolite2", "ipapi") \
                and _cache_valid(info.get("cached_at", "-")):
            result[ip_map[ip]] = info
        else:
            uncached.append(ip)

    if uncached:
        if mmdb_available():
            # 主源：GeoLite2 本地库
            for ip in uncached:
                info = _GEOLITE2.lookup(ip)
                info["source"] = "geolite2"
                info["cached_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                result[ip] = info
                _write_cache(ip, info)
        else:
            # 兜底：ip-api（在线、有限流）
            hits = _query_ipapi_batch(uncached, proxies=proxies)
            for ip in uncached:
                info = hits.get(ip)
                if not info:
                    info = {
                        "asn": "-", "country": "-", "country_code": "-", "country_cn": "-",
                        "region_name": "-", "city": "-", "continent": "-", "flag": "-",
                        "org": "-",
                    }
                info["source"] = "ipapi"
                info["cached_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                result[ip] = info
                _write_cache(ip, info)

    # 兜底标 -（纯防御，正常不会走到）
    for ip in pure_ips:
        if ip not in result:
            info = {
                "asn": "-", "country": "-", "country_code": "-", "country_cn": "-",
                "region_name": "-", "city": "-", "continent": "-", "flag": "-",
                "org": "-", "source": "ipapi", "cached_at": "-",
            }
            result[ip] = info

    return result


def _query_ipapi_batch(ips: list[str], proxies: dict | None = None) -> dict:
    """ip-api.com batch 兜底查询。

    org 从 `as` 字段解析（AS号+组织名同源），不用不可靠的 org 字段；
    country_cn/continent/flag 由 country_code 查静态表派生。
    """
    import json
    import re
    import urllib.request

    if not ips:
        return {}

    result = {}
    FIELDS = "status,message,query,as,country,countryCode,regionName,city"
    # ip-api batch ≤100/批；免费版限流，逐批串行 + 礼貌间隔
    for i in range(0, len(ips), 100):
        batch = ips[i:i + 100]
        url = f"http://ip-api.com/batch?fields={FIELDS}"
        data = json.dumps(batch).encode()
        try:
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"},
            )
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler(proxies or {})
            )
            with opener.open(req, timeout=15) as resp:
                entries = json.loads(resp.read())
            for entry in entries:
                ip = entry.get("query", "")
                if not ip or entry.get("status") != "success":
                    continue
                as_str = entry.get("as", "")
                m = re.search(r"AS(\d+)\s+(.+)", as_str)
                if m:
                    asn = int(m.group(1))
                    org = m.group(2).strip()
                else:
                    asn = "-"
                    org = "-"
                cc = entry.get("countryCode", "-")
                country = entry.get("country", "-")
                result[ip] = {
                    "asn": asn,
                    "org": org,
                    "country": country,
                    "country_code": cc,
                    "country_cn": COUNTRY_CN.get(cc, country),
                    "region_name": entry.get("regionName", "-"),
                    "city": entry.get("city", "-"),
                    "continent": COUNTRY_REGION.get(cc, "-"),
                    "flag": COUNTRY_FLAG.get(cc, _country_code_to_flag(cc) or "-"),
                }
        except Exception as e:
            print(f"  ⚠ ip-api 兜底查询失败 ({len(batch)} IP): {e}")
        if i + 100 < len(ips):
            time.sleep(1.0)  # 免费版限流礼貌间隔
    return result


def _read_cache(ip: str) -> dict | None:
    """读取缓存。新格式含 country_cn/continent/flag；旧格式缺失字段补 '-'。"""
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
                "country_code": "-", "region_name": "-", "city": "-",
                "country_cn": "-", "continent": "-", "flag": "-",
            }
            if len(parts) >= 8:
                result["country_code"] = parts[5]
                result["region_name"] = parts[6]
                result["city"] = parts[7]
            if len(parts) >= 11:
                result["country_cn"] = parts[8]
                result["continent"] = parts[9]
                result["flag"] = parts[10]
            else:
                # 旧缓存补派生字段（country_code 有值就能推）
                cc = result["country_code"]
                if cc and cc != "-":
                    result["country_cn"] = COUNTRY_CN.get(cc, "-")
                    result["continent"] = COUNTRY_REGION.get(cc, "-")
                    result["flag"] = COUNTRY_FLAG.get(cc, _country_code_to_flag(cc) or "-")
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
            info.get("country_cn", "-"),
            info.get("continent", "-"),
            info.get("flag", "-"),
        ]) + "\n")
