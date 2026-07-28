"""① ASN → CIDR

从 RIPEStat / BGPView 获取指定 ASN 的广播 IPv4 段。
缓存 24h，支持多 ASN 并发请求。
"""

import time
import ipaddress
import urllib.request
import urllib.error
import json
import os
from pathlib import Path

from .utils import log, CACHE_DIR, atomic_write

# ── 数据源 ────────────────────────────────────────────────────────────
RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
BGPViEW_URL = "https://api.bgpview.io/asn/{asn}/prefixes"


def _fetch_json(url: str, timeout: int = 15) -> dict | None:
    """请求 JSON 数据，返回 dict 或 None"""
    req = urllib.request.Request(url, headers={"User-Agent": "ASNIPtest/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        log.warning(f"  HTTP 请求失败 [{url}]: {e}")
        return None


def _fetch_ripestat(asn: str) -> list[str] | None:
    """从 RIPEStat 获取 CIDR 列表（IPv4 only）"""
    url = RIPESTAT_URL.format(asn=asn)
    data = _fetch_json(url)
    if not data or "data" not in data:
        return None
    prefixes = data["data"].get("prefixes", [])
    cidrs = []
    for p in prefixes:
        cidr = p.get("prefix", "")
        # IPv4 only — 过滤含 : 的 IPv6
        if cidr and ":" not in cidr:
            cidrs.append(cidr)
    return cidrs if cidrs else None


def _fetch_bgpview(asn: str) -> list[str] | None:
    """从 BGPView 获取 CIDR 列表（IPv4 only）"""
    url = BGPViEW_URL.format(asn=asn)
    data = _fetch_json(url)
    if not data or "data" not in data:
        return None
    prefixes = data["data"].get("ipv4_prefixes", [])
    cidrs = [p.get("prefix", "") for p in prefixes if p.get("prefix")]
    return cidrs if cidrs else None


def _validate_cidr(cidr: str) -> bool:
    """校验 CIDR 是否合法"""
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        # 过滤不可扫描网段
        if net.is_private:
            return False
        if net.is_loopback:
            return False
        if net.is_link_local:
            return False
        if net.is_reserved:
            return False
        if net.is_multicast:
            return False
        if net.is_unspecified:
            return False
        # CGNAT 100.64/10 — is_private 不一定覆盖
        if net.network_address.packed[0] == 100 and (net.prefixlen <= 10):
            return False
        return True
    except Exception:
        return False


def fetch_cidrs(asn: str, force: bool = False) -> list[str]:
    """获取ASN的IPv4 CIDR列表（已去重+过滤不可扫）

    Args:
        asn: AS 号（纯数字，如 "13335"）
        force: 是否跳过缓存

    Returns:
        合法 CIDR 字符串列表
    """
    # 缓存路径
    cache_file = CACHE_DIR / f"cidr_AS{asn}.txt"

    # 读缓存（非 force 且缓存存在且未过期）
    if not force and cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < 86400:  # 24h
            cidrs = cache_file.read_text().strip().splitlines()
            cidrs = [c.strip() for c in cidrs if c.strip()]
            if cidrs:
                log.info(f"  AS{asn}: 从缓存读取 {len(cidrs)} 个 CIDR")
                return cidrs
            else:
                log.info(f"  AS{asn}: 缓存为空，重新抓取")

    # 在线抓取 — RIPEStat 主，重试 2 次后退到 BGPView
    cidrs = None
    sources = []
    for attempt in range(3):
        log.info(f"  AS{asn}: 查询 RIPEStat (尝试 {attempt + 1}/3)...")
        cidrs = _fetch_ripestat(asn)
        if cidrs:
            sources.append("RIPEStat")
            break
        if attempt < 2:
            wait = 2 ** attempt
            log.info(f"  AS{asn}: 等待 {wait}s 后重试...")
            time.sleep(wait)

    # RIPEStat 失败 → BGPView 兜底
    if not cidrs:
        log.info(f"  AS{asn}: RIPEStat 失败，切到 BGPView...")
        cidrs = _fetch_bgpview(asn)
        if cidrs:
            sources.append("BGPView")

    if not cidrs:
        log.error(f"  AS{asn}: 所有数据源均失败，无法获取 CIDR")
        return []

    # 校验 + 过滤不可扫
    valid = [c for c in cidrs if _validate_cidr(c)]
    invalid = len(cidrs) - len(valid)
    if invalid:
        log.info(f"  AS{asn}: 过滤掉 {invalid} 个不可扫网段")

    # 去重
    unique = sorted(set(valid))

    # 写缓存
    atomic_write(str(cache_file), "\n".join(unique) + "\n")
    log.info(f"  AS{asn}: 获取 {len(unique)} 个合法 CIDR (来源: {','.join(sources)})")

    return unique


def fetch_multiple(asn_list: list[str], force: bool = False) -> dict[str, list[str]]:
    """批量获取多个 ASN 的 CIDR（顺序执行，避免触发限流）

    Returns:
        {asn: [cidr, ...]}
    """
    result = {}
    for asn in asn_list:
        asn = asn.strip()
        if not asn.isdigit():
            log.warning(f"  AS 号不合法: {asn}，跳过")
            continue
        cidrs = fetch_cidrs(asn, force=force)
        result[asn] = cidrs
    return result


# ── 直接运行测试 ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("用法: python -m pipeline.step1_cidr <ASN> [ASN2 ...]")
        sys.exit(1)

    for asn in sys.argv[1:]:
        print(f"\n=== AS{asn} ===")
        cidrs = fetch_cidrs(asn)
        print(f"共 {len(cidrs)} 个 CIDR")
        for c in cidrs[:5]:
            print(f"  {c}")
        if len(cidrs) > 5:
            print(f"  ... 还有 {len(cidrs) - 5} 个")
