"""⑥ output：合并各阶段产物生成最终报告。"""
import csv
import json
import os


def _access_protocol(tls: str, alpn: str, cf_confirmed: bool = False) -> str:
    """推断访问协议：https / http / plaintext。

    优先用实际字段；cf-scanner 验证通过的节点支持 TLS，
    但端到端可能是 plaintext 回源，所以保留原始值，不再强制 https。
    """
    if tls and tls not in ("-", "", "false", "False"):
        return tls.lower()
    if alpn and alpn not in ("-", ""):
        return "https"
    if cf_confirmed:
        return "https"
    return "plaintext"


def generate_report(ip_data: list[dict], output_dir: str = ".",
                    top_n: int | None = None,
                    keep_cf_official: bool = False,
                    json_output: bool = False,
                    public_ip: str = "-",
                    colo_map: dict | None = None,
                    basename: str | None = None) -> dict:
    """生成最终报告（14 列）。
    ...
    """
    os.makedirs(output_dir, exist_ok=True)

    # 默认文件名 report.csv，可选自定义 basename
    name = basename or "report"
    csv_path = os.path.join(output_dir, f"{name}.csv")
    json_path = os.path.join(output_dir, f"{name}.json") if json_output else None

    # 排序：延迟升序（快的在前）
    def sort_key(row):
        lat = row.get("latency_ms", 99999)
        if isinstance(lat, str) or lat == "-":
            lat = 99999
        return lat

    rows = sorted(ip_data, key=sort_key)

    # 过滤 CF 官方
    if not keep_cf_official:
        rows = [r for r in rows if not r.get("is_cf_official", False)]

    # 去重：同一 ip:port 只保留一条（测速前已去重，这里为兜底，无优先逻辑）
    _seen = set()
    rows = [r for r in rows if r.get("ip_port", "") not in _seen and not _seen.add(r.get("ip_port", ""))]
    rows.sort(key=sort_key)  # 去重后重新按延迟升序输出

    # top N
    if top_n and top_n > 0:
        rows = rows[:top_n]

    # === 写 CSV ===
    # 14 列：已删「数据中心」；「地区(中文)」→「大陆」；「城市(中文)」→「国家(中文)」
    fieldnames = [
        "IP地址", "端口号", "TLS", "IP位置",
        "地区", "城市", "大陆", "国家(中文)", "国旗",
        "网络延迟(ms)",
        "ASN号码", "ASN组织", "访问协议", "测速",
    ]

    csv_path = os.path.join(output_dir, f"{name}.csv")
    json_path = os.path.join(output_dir, f"{name}.json") if json_output else None
    # 用 utf-8-sig 写 BOM，Windows Excel 才能正确识别 UTF-8（否则按 GBK 打开显示乱码）
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)
        for row in rows:
            ip, port = _split_ip_port(row.get("ip_port", ""))
            ip_port_str = row.get("ip_port", "")
            is_cf_row = row.get("verify_conf") in ("high", "low")
            lat = row.get("latency_ms", "-")
            dl = row.get("download_mbps", 0)
            # 测速列只填实际下载速率；无测速(速率)则留空，不回填延迟数据
            if dl and dl > 0:
                speed_str = f"{dl} Mbps"
            else:
                speed_str = "-"
            # 访问协议：优先按实际字段推断
            if row.get("tls", "-") not in ("-", "", "false", "False"):
                proto = row["tls"].lower()
            elif row.get("alpn", "-") not in ("-", ""):
                proto = "https"
            elif is_cf_row or row.get("verify_status") in ("200", "301", "403"):
                proto = "https"
            else:
                proto = "plaintext"

            # 派生列直接用 ④ enrich 的同源字段（GeoLite2），不再查 utils 静态表
            continent = row.get("continent", "-") or "-"
            country_cn = row.get("country_cn", "-") or "-"
            flag = row.get("flag", "-") or "-"

            org_val = row.get("org", "-") or "-"
            writer.writerow([
                ip,
                port,
                "true" if is_cf_row else row.get("tls", "-"),
                row.get("country", "-"),
                row.get("region_name", "-"),
                row.get("city", "-"),
                continent,
                country_cn,
                flag,
                lat,
                row.get("asn", "-"),
                org_val,
                proto,
                speed_str,
            ])

    # === 写 JSON ===
    if json_output:
        json_rows = []
        for row in rows:
            ip, port = _split_ip_port(row.get("ip_port", ""))
            cc = row.get("country_code", "-")
            ip_port_str = row.get("ip_port", "")
            is_cf = row.get("verify_conf") in ("high", "low")
            if row.get("tls", "-") not in ("-", "", "false", "False"):
                proto = row["tls"].lower()
            elif row.get("alpn", "-") not in ("-", ""):
                proto = "https"
            elif is_cf or row.get("verify_status") in ("200", "301", "403"):
                proto = "https"
            else:
                proto = "plaintext"
            json_rows.append({
                "ip": ip,
                "port": port,
                "tls": "true" if is_cf else row.get("tls", "-"),
                "country": row.get("country", "-"),
                "country_code": cc,
                "region_name": row.get("region_name", "-"),
                "city": row.get("city", "-"),
                "continent": row.get("continent", "-"),
                "country_cn": row.get("country_cn", "-"),
                "flag": row.get("flag", "-"),
                "latency_ms": row.get("latency_ms", "-"),
                "public_ip": ip,
                "ip_type": "IPv4" if ":" not in ip else "IPv6",
                "ip_category": row.get("ip_type", "未知"),
                "asn": row.get("asn", "-"),
                "org": row.get("org", "-"),
                "protocol": proto,
            })
        # 与 CSV 同名（只差扩展名），遵循 basename
        json_basename = name  # name = basename or "report"
        json_path = os.path.join(output_dir, f"{json_basename}.json")
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
