"""⑥ output：合并各阶段产物生成最终报告。"""
import csv
import json
import os


def generate_report(ip_data: list[dict], output_dir: str = ".", top_n: int | None = None,
                    keep_cf_official: bool = False, json_output: bool = False) -> dict:
    """生成最终报告。

    ip_data: [{"ip_port", "asn", "country", "org", "is_cf_official",
               "latency_ms", "download_mbps", "tls", "alpn",
               "verify_reason", "confidence"}, ...]
    output_dir: 输出目录
    top_n: 只输出前 N 个
    keep_cf_official: True 则保留 CF 官方行
    json_output: True 则额外生成 JSON
    """
    os.makedirs(output_dir, exist_ok=True)

    # 排序：download 降序 → latency 升序
    def sort_key(row):
        dl = row.get("download_mbps", 0) or 0
        lat = row.get("latency_ms", 99999) or 99999
        if isinstance(lat, str):
            lat = 99999
        return (-dl, lat)

    rows = sorted(ip_data, key=sort_key)

    # 过滤 CF 官方
    if not keep_cf_official:
        rows = [r for r in rows if not r.get("is_cf_official", False)]

    # top N
    if top_n and top_n > 0:
        rows = rows[:top_n]

    # 列定义
    fieldnames = [
        "IP", "PORT", "Latency_ms", "Download_Mbps",
        "ASN", "Country", "Org", "Is_CF_Official",
        "TLS", "ALPN", "Verify_Reason", "Confidence",
    ]

    # 写 CSV
    csv_path = os.path.join(output_dir, "report.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)
        for row in rows:
            ip, port = _split_ip_port(row.get("ip_port", ""))
            writer.writerow([
                ip, port,
                row.get("latency_ms", "-"),
                row.get("download_mbps", 0),
                row.get("asn", "-"),
                row.get("country", "-"),
                row.get("org", "-"),
                "Yes" if row.get("is_cf_official") else "No",
                row.get("tls", "-"),
                row.get("alpn", "-"),
                row.get("verify_reason", "-"),
                row.get("confidence", "-"),
            ])

    # 写 JSON
    if json_output:
        json_path = os.path.join(output_dir, "report.json")
        json_rows = []
        for row in rows:
            ip, port = _split_ip_port(row.get("ip_port", ""))
            json_rows.append({
                "ip": ip,
                "port": port,
                "latency_ms": row.get("latency_ms", "-"),
                "download_mbps": row.get("download_mbps", 0),
                "asn": row.get("asn", "-"),
                "country": row.get("country", "-"),
                "org": row.get("org", "-"),
                "is_cf_official": row.get("is_cf_official", False),
                "tls": row.get("tls", "-"),
                "alpn": row.get("alpn", "-"),
                "verify_reason": row.get("verify_reason", "-"),
                "confidence": row.get("confidence", "-"),
            })
        with open(json_path, "w") as f:
            json.dump(json_rows, f, indent=2)

    stats = {
        "total_input": len(ip_data),
        "cf_official": sum(1 for r in ip_data if r.get("is_cf_official")),
        "with_speed": sum(1 for r in rows if r.get("latency_ms") != "-"),
        "final_output": len(rows),
        "csv_path": csv_path,
        "json_path": json_path if json_output else None,
    }

    return stats


def _split_ip_port(ip_port: str) -> tuple:
    if ":" in ip_port:
        parts = ip_port.rsplit(":", 1)
        return parts[0], parts[1]
    return ip_port, ""
