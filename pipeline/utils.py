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
# ============================================================
# IP 类型分类 + 地区/国旗映射（输出报告用，不改主流程）
# ============================================================

# 机房/住宅 IP 类型关键词（Org 字段匹配）
# CF 官方 IP 由 is_cf_official 字段单独标记，不在本分类中出现
IP_TYPE_KEYWORDS: dict[str, list[str]] = {
    "机房": [
        "amazon", "aws", "google", "gcp", "gce", "cloud",
        "equinix", "colo", "hosting", "vultr", "digitalocean",
        "linode", "scaleway", "bandwagon", "leaseweb", "ovh",
        "softlayer", "alibaba", "azure", "sakura", "hetzner",
        "ip-172", "ip-10-", "ip-100-", "ip-139-", "ip-142-",
        "ip-143-", "ip-185-", "ip-208-", "ip-209-", "ip-172-26",
        "ip-172-27", "ip-172-28", "ip-172-29", "ip-172-30",
        "ip-172-31", "ip-172-32", "ip-172-33", "ip-172-34",
        "ip-172-35", "ip-172-36", "ip-172-37", "ip-172-38",
        "ip-172-39", "ip-172-40", "ip-172-41", "ip-172-42",
        "ip-172-43", "ip-172-44", "ip-172-45", "ip-172-46",
        "ip-172-47", "ip-172-48", "ip-172-49", "ip-172-50",
        "aws ec2", "ec2-", "a40348", "datacenter", "data center",
        "compute", "g2", "ip-3-", "ip-34-", "ip-35-", "ip-52-",
        "ip-54-", "ip-66-", "ip-68-", "ip-70-", "ip-71-",
        "ip-72-", "ip-74-", "ip-75-", "ip-76-", "ip-78-",
        "ip-79-", "ip-88-", "ip-99-", "ip-103-", "ip-104-",
        "ip-110-", "ip-112-", "ip-113-", "ip-116-", "ip-117-",
        "ip-118-", "ip-119-", "ip-120-", "ip-126-", "ip-127-",
        "ip-128-", "ip-129-", "ip-130-", "ip-136-",
    ],
    "住宅": [
        # 国外住宅 ISP（不含中国运营商）
        "comcast", "verizon", "at&t", "att ub", "att umts",
        "att wireless", "att corp", "ntt", "kt corporation",
        "sk telecom", "sktel", "optus", "singtel", "telstra",
        "vodafone", "orange", "telecom", "broadband",
        "residential", "dsl", "cable", "fiber",
        "isp", "communication",
    ],
}


def classify_ip_type(org: str, asn: int | str = "-") -> str:
    """根据 Org + ASN 判断 IP 类型：机房/住宅/未知。

    CF 官方 IP（asn ∈ CF_OFFICIAL_ASNS）由调用方用 is_cf_official 处理，
    本函数不判断 CF 官方。
    """
    if not org or org == "-":
        return "未知"
    org_lower = org.lower()
    for label, keywords in IP_TYPE_KEYWORDS.items():
        if any(kw in org_lower for kw in keywords):
            return label
    return "未知"


# ISO 两位国家码 → 国旗 emoji（零依赖）
COUNTRY_FLAG: dict[str, str] = {
    "HK": "🇭🇰", "MO": "🇲🇴", "TW": "🇹🇼", "CN": "🇨🇳",
    "JP": "🇯🇵", "KR": "🇰🇷", "SG": "🇸🇬", "MY": "🇲🇾",
    "TH": "🇹🇭", "PH": "🇵🇭", "VN": "🇻🇳", "ID": "🇮🇩",
    "IN": "🇮🇳", "US": "🇺🇸", "GB": "🇬🇧", "DE": "🇩🇪",
    "FR": "🇫🇷", "CA": "🇨🇦", "AU": "🇦🇺", "NZ": "🇳🇿",
    "NL": "🇳🇱", "SE": "🇸🇪", "NO": "🇳🇴", "DK": "🇩🇰",
    "FI": "🇫🇮", "IE": "🇮🇪", "ES": "🇪🇸", "IT": "🇮🇹",
    "CH": "🇨🇭", "AT": "🇦🇹", "BE": "🇧🇪", "PL": "🇵🇱",
    "RU": "🇷🇺", "UA": "🇺🇦", "RO": "🇷🇴", "BG": "🇧🇬",
    "HU": "🇭🇺", "CZ": "🇨🇿", "UA": "🇺🇦",
    "TR": "🇹🇷", "AE": "🇦🇪", "SA": "🇸🇦", "IL": "🇮🇱",
    "BR": "🇧🇷", "MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱",
    "ZA": "🇿🇦", "EG": "🇪🇬", "KE": "🇰🇪", "NG": "🇳🇬",
    "NZ": "🇳🇿",
}


# 国家码 → 中文名称
COUNTRY_CN: dict[str, str] = {
    "HK": "香港", "MO": "澳门", "TW": "台湾", "CN": "中国大陆",
    "JP": "日本", "KR": "韩国", "SG": "新加坡", "MY": "马来西亚",
    "TH": "泰国", "PH": "菲律宾", "VN": "越南", "ID": "印度尼西亚",
    "IN": "印度", "US": "美国", "GB": "英国", "DE": "德国",
    "FR": "法国", "CA": "加拿大", "AU": "澳大利亚", "NZ": "新西兰",
    "NL": "荷兰", "SE": "瑞典", "NO": "挪威", "DK": "丹麦",
    "FI": "芬兰", "IE": "爱尔兰", "ES": "西班牙", "IT": "意大利",
    "CH": "瑞士", "AT": "奥地利", "BE": "比利时", "PL": "波兰",
    "RU": "俄罗斯", "UA": "乌克兰", "RO": "罗马尼亚", "BG": "保加利亚",
    "HU": "匈牙利", "CZ": "捷克",
    "TR": "土耳其", "AE": "阿联酋", "SA": "沙特", "IL": "以色列",
    "BR": "巴西", "MX": "墨西哥", "AR": "阿根廷", "CL": "智利",
    "ZA": "南非", "EG": "埃及", "KE": "肯尼亚", "NG": "尼日利亚",
}


# 国家码 → 地区名称（Asia Pacific / North America / Europe / South America 等）
COUNTRY_REGION: dict[str, str] = {
    "HK": "亚洲/太平洋", "MO": "亚洲/太平洋", "TW": "亚洲/太平洋",
    "CN": "亚洲/太平洋", "JP": "亚洲/太平洋", "KR": "亚洲/太平洋",
    "SG": "亚洲/太平洋", "MY": "亚洲/太平洋", "TH": "亚洲/太平洋",
    "PH": "亚洲/太平洋", "VN": "亚洲/太平洋", "ID": "亚洲/太平洋",
    "IN": "亚洲/太平洋",
    "US": "北美洲", "CA": "北美洲", "MX": "北美洲",
    "BR": "南美洲", "AR": "南美洲", "CL": "南美洲",
    "GB": "欧洲", "DE": "欧洲", "FR": "欧洲", "NL": "欧洲",
    "SE": "欧洲", "NO": "欧洲", "DK": "欧洲", "FI": "欧洲",
    "IE": "欧洲", "ES": "欧洲", "IT": "欧洲", "CH": "欧洲",
    "AT": "欧洲", "BE": "欧洲", "PL": "欧洲", "RU": "欧洲",
    "UA": "欧洲", "RO": "欧洲", "BG": "欧洲", "HU": "欧洲", "CZ": "欧洲",
    "AU": "大洋洲", "NZ": "大洋洲",
    "TR": "欧亚", "AE": "中东", "SA": "中东", "IL": "中东",
    "ZA": "非洲", "EG": "非洲", "KE": "非洲", "NG": "非洲",
}
