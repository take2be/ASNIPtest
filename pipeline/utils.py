"""ASNIPtest 管线基础工具."""
import ipaddress
import os
import re

# 不可扫描网段
UNSCANNABLE_NETS = [
    ipaddress.IPv4Network("0.0.0.0/8"),        # "This" network
    ipaddress.IPv4Network("10.0.0.0/8"),       # Private
    ipaddress.IPv4Network("100.64.0.0/10"),    # CGNAT
    ipaddress.IPv4Network("127.0.0.0/8"),      # Loopback
    ipaddress.IPv4Network("169.254.0.0/16"),   # Link-local
    ipaddress.IPv4Network("172.16.0.0/12"),    # Private
    ipaddress.IPv4Network("192.0.2.0/24"),     # Documentation (TEST-NET-1)
    ipaddress.IPv4Network("192.168.0.0/16"),   # Private
    ipaddress.IPv4Network("198.18.0.0/15"),    # Benchmarking
    ipaddress.IPv4Network("203.0.113.0/24"),   # Documentation (TEST-NET-3)
    ipaddress.IPv4Network("224.0.0.0/4"),      # Multicast
    ipaddress.IPv4Network("240.0.0.0/4"),      # Reserved
]

# CF 官方 ASN（外置配置默认值，项目根 config/cf_official_asns.txt 可覆盖）
CF_OFFICIAL_ASNS_DEFAULT = [
    13335, 395747, 132892, 202623, 133877,
    139242, 203898, 394536, 400095, 14789,
    209242, 204829, 200242,
]

CACHE_DIR = "cache"
CONFIG_DIR = "config"


def ensure_dirs():
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(CONFIG_DIR, exist_ok=True)


def load_cf_official_asns(path="config/cf_official_asns.txt"):
    """加载 CF 官方 ASN 清单。文件不存在则用默认值。"""
    if not os.path.exists(path):
        return set(CF_OFFICIAL_ASNS_DEFAULT)
    asns = set()
    with open(path) as f:
        for line in f:
            m = re.search(r"AS?(\d+)", line.strip())
            if m:
                asns.add(int(m.group(1)))
    return asns or set(CF_OFFICIAL_ASNS_DEFAULT)


def is_scannable(prefix: str) -> bool:
    """判断 CIDR 是否可扫描（非保留/私有/多播等）。"""
    net = ipaddress.IPv4Network(prefix, strict=False)
    for banned in UNSCANNABLE_NETS:
        if net.overlaps(banned):
            return False
    return True


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"
