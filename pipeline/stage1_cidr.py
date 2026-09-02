"""① ASN → CIDR：从 RIPEStat / BGPView 获取 ASN 广播段。

用法:
    from pipeline.stage1_cidr import fetch_cidrs
    prefixes = fetch_cidrs([13335, 209554])
"""
import ipaddress
import json
import os
import time
import urllib.error
import urllib.request

from .utils import is_scannable, ensure_dirs, CACHE_DIR


def fetch_cidrs(asns: list[int], force: bool = False, proxies: dict | None = None) -> list[str]:
    """获取一个或多个 ASN 的 IPv4 CIDR 列表。返回去重+过滤后的可扫描段。

    Args:
        asns: ASN 号列表
        force: 强制忽略缓存
        proxies: 代理设置，如 {"http": "http://127.0.0.1:10808", "https": ...}
    """
    ensure_dirs()
    seen = set()
    result = []

    for asn in asns:
        prefixes = _fetch_single(asn, force=force, proxies=proxies)
        for p in prefixes:
            if p not in seen and is_scannable(p):
                seen.add(p)
                result.append(p)

    result.sort(key=lambda x: (ipaddress.IPv4Network(x, strict=False).network_address))
    return result


def _fetch_single(asn: int, force: bool = False, proxies: dict | None = None) -> list[str]:
    """查单个 ASN 的 IPv4 前缀。有缓存读缓存，否则在线查。"""
    # 检查缓存
    cache_file = os.path.join(CACHE_DIR, f"cidr_AS{asn}.txt")
    if not force and os.path.exists(cache_file):
        age = time.time() - os.path.getmtime(cache_file)
        if age < 172800:  # 48h TTL
            with open(cache_file) as f:
                return [l.strip() for l in f if l.strip()]

    # 在线查：主 RIPEStat → 备 BGPView
    prefixes = _query_ripestat(asn, proxies=proxies)
    if prefixes is None:
        prefixes = _query_bgpview(asn, proxies=proxies)
    if prefixes is None:
        print(f"  ⚠ AS{asn}: 所有数据源查询失败")
        return []

    # 写缓存
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(cache_file, "w") as f:
        for p in prefixes:
            f.write(p + "\n")

    return prefixes


def _query_ripestat(asn: int, proxies: dict | None = None) -> list[str] | None:
    """主源：RIPEStat API。重试 2 次后失败返回 None。"""
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ASNIPtest/1.0"})
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler(proxies or {})
            )
            with opener.open(req, timeout=15) as resp:
                data = json.loads(resp.read())
            prefixes = []
            for entry in data.get("data", {}).get("prefixes", []):
                p = entry.get("prefix", "")
                if p and ":" not in p:  # 仅 IPv4
                    # 统一移除掩码前的空格
                    p = p.replace(" ", "")
                    try:
                        ipaddress.IPv4Network(p, strict=False)
                        prefixes.append(p)
                    except (ValueError, TypeError):
                        pass
            return prefixes if prefixes else None
        except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
            if attempt < 2:
                wait = 2 ** attempt
                print(f"  ⚠ RIPEStat AS{asn} 超时(尝试 {attempt+1}/3), {wait}s 后重试: {e}")
                time.sleep(wait)
            else:
                print(f"  ✗ RIPEStat AS{asn} 失败(3次): {e}")
    return None


def _query_bgpview(asn: int, proxies: dict | None = None) -> list[str] | None:
    """备源：BGPView API。"""
    url = f"https://api.bgpview.io/asn/AS{asn}/prefixes"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ASNIPtest/1.0"})
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(proxies or {})
        )
        with opener.open(req, timeout=15) as resp:
            data = json.loads(resp.read())
        prefixes = []
        for entry in data.get("data", {}).get("ipv4_prefixes", []):
            p = entry.get("prefix", "")
            if p:
                try:
                    ipaddress.IPv4Network(p, strict=False)
                    prefixes.append(p)
                except (ValueError, TypeError):
                    pass
        return prefixes if prefixes else None
    except Exception as e:
        print(f"  ✗ BGPView AS{asn} 失败: {e}")
        return None
