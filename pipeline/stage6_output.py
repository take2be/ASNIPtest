"""⑥ output：合并各阶段产物生成最终报告。"""
import csv
import json
import os

from .utils import COUNTRY_FLAG, COUNTRY_CN, COUNTRY_REGION


def _country_flag(country_code: str) -> str:
    """国家码 → 国旗 emoji。"""
    return COUNTRY_FLAG.get(country_code, "")


def _country_cn(country_code: str) -> str:
    """国家码 → 中文名称。"""
    return COUNTRY_CN.get(country_code, country_code)


def _country_region(country_code: str) -> str:
    """国家码 → 地区名称（亚洲/太平洋 等）。"""
    return COUNTRY_REGION.get(country_code, country_code)


def _access_protocol(tls: str, alpn: str) -> str:
    """推断访问协议：https / http / plaintext。"""
    if tls and tls != "-":
        return "https"
    if alpn and alpn != "-":
        return "https"
    return "plaintext"


def generate_report(ip_data: list[dict], output_dir: str = ".",
                    top_n: int | None = None,
                    keep_cf_official: bool = False,
                    json_output: bool = False,
                    public_ip: str = "-",
                    colo_map: dict | None = None) -> dict:
    """生成最终报告（17 列）。

    列顺序（用户指定，不含 WARP/Gateway/RBI/密钥交换/时间戳）:
        IP地址 | 端口号 | TLS | 数据中心 | IP位置 | 地区 | 城市
        | 地区(中文) | 城市(中文) | 国旗 | 网络延迟 | 出站IP | 出站IP类型
        | IP类型(机房/住宅) | ASN号码 | ASN组织 | 访问协议
    """
    os.makedirs(output_dir, exist_ok=True)

    # 排序：download 降序 → latency 升序
    def sort_key(row):
        dl = row.get("download_mbps", 0) or 0
        lat = row.get("latency_ms", 99999)
        if isinstance(lat, str) or lat == "-":
            lat = 99999
        return (-dl, lat)

    rows = sorted(ip_data, key=sort_key)

    # 过滤 CF 官方
    if not keep_cf_official:
        rows = [r for r in rows if not r.get("is_cf_official", False)]

    # top N
    if top_n and top_n > 0:
        rows = rows[:top_n]

    # === 写 CSV ===
    fieldnames = [
        "IP地址", "端口号", "TLS", "数据中心", "IP位置",
        "地区", "城市", "地区(中文)", "城市(中文)", "国旗",
        "网络延迟(ms)", "出站IP", "出站IP类型", "IP类型",
        "ASN号码", "ASN组织", "访问协议",
    ]

    csv_path = os.path.join(output_dir, "report.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)
        for row in rows:
            ip, port = _split_ip_port(row.get("ip_port", ""))
            cc = row.get("country_code", "-")
            cn_flag = _country_flag(cc)
            cn_name = _country_cn(cc)
            region = _country_region(cc)
            ip_port_str = row.get("ip_port", "")
            # 出站IP类型：判断 IP 部分（不含端口）
            ip_only = ip_port_str.rsplit(":", 1)[0] if ":" in ip_port_str else ip_port_str
            ip_port_type = "IPv6" if ":" in ip_only else "IPv4"
            proto = _access_protocol(
                row.get("tls", "-"), row.get("alpn", "-"))

            writer.writerow([
                ip,                           # IP地址
                port,                         # 端口号
                row.get("tls", "-"),          # TLS
                row.get("colo", "-"),          # 数据中心(colo, cf-scanner)
                row.get("country", "-"),       # IP位置
                row.get("region_name", "-"),  # 地区
                row.get("city", "-"),         # 城市
                region,                       # 地区(中文)
                cn_name,                      # 城市(中文) — ip-api 不返城市中文，用国家中文兜底
                cn_flag,                      # 国旗
                row.get("latency_ms", "-"),   # 网络延迟(ms)
                public_ip,                    # 出站IP
                ip_port_type,                 # 出站IP类型
                row.get("ip_type", "未知"),   # IP类型(机房/住宅/CF官方)
                row.get("asn", "-"),          # ASN号码
                row.get("org", "-"),          # ASN组织
                proto,                        # 访问协议
            ])

    # === 写 JSON ===
    if json_output:
        json_rows = []
        for row in rows:
            ip, port = _split_ip_port(row.get("ip_port", ""))
            cc = row.get("country_code", "-")
            ip_port_str = row.get("ip_port", "")
            ip_only = ip_port_str.rsplit(":", 1)[0] if ":" in ip_port_str else ip_port_str
            ip_version = "IPv6" if ":" in ip_only else "IPv4"
            proto = _access_protocol(
                row.get("tls", "-"), row.get("alpn", "-"))
            json_rows.append({
                "ip": ip,
                "port": port,
                "tls": row.get("tls", "-"),
                "colo": row.get("colo", "-"),
                "country": row.get("country", "-"),
                "country_code": cc,
                "region_name": row.get("region_name", "-"),
                "city": row.get("city", "-"),
                "country_cn": _country_cn(cc),
                "region_cn": _country_region(cc),
                "flag": _country_flag(cc),
                "latency_ms": row.get("latency_ms", "-"),
                "public_ip": ip,
                "ip_type": ip_version,
                "ip_category": row.get("ip_type", "未知"),
                "asn": row.get("asn", "-"),
                "org": row.get("org", "-"),
                "protocol": proto,
            })
        json_path = os.path.join(output_dir, "report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_rows, f, indent=2, ensure_ascii=False)
    else:
        json_path = None

    stats = {
        "total_input": len(ip_data),
        "cf_official": sum(1 for r in ip_data if r.get("is_cf_official")),
        "with_speed": sum(1 for r in rows if r.get("latency_ms") not in ("-", None)),
        "final_output": len(rows),
        "csv_path": csv_path,
        "json_path": json_path,
    }

    return stats


def _split_ip_port(ip_port: str) -> tuple:
    if ":" in ip_port:
        parts = ip_port.rsplit(":", 1)
        return parts[0], parts[1]
    return ip_port, ""
