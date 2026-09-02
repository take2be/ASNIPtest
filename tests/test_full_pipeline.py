"""全流程 monkey 模拟实测：用 monkeypatch 替换所有外部依赖（网络/二进制），
让 ①→⑥ 全管线真实跑通，验证：
  - 各命令/阶段能正常推进不崩
  - 最终输出文件命名 = AS{asn}_{ports}_{时间戳}.csv
  - CSV 列数/内容正确
  - HTTP 下载服务能返回真实 CSV
  - --json 时生成 .json

运行: pytest tests/test_full_pipeline.py -v -s
"""
import csv
import glob
import io
import os
import re
import shutil
import sys
import time
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import asnip
from pipeline import stage1_cidr, stage2_masscan, stage4_enrich, stage5_speed


# ---- 假数据 ----
FAKE_CIDRS = ["1.0.0.0/24", "2.0.0.0/24"]
FAKE_TARGETS = ["9.9.9.9:443", "9.9.9.10:8443", "9.9.9.11:2053"]


def _fake_fetch_cidrs(asns, force=False, proxies=None):
    return list(FAKE_CIDRS)


def _fake_run_masscan(block_index, cidrs_file, ports, workdir, rate=2000):
    """模拟 masscan：直接写 JSON 结果文件，返回成功。"""
    out = os.path.join(workdir, f"block_{block_index:03d}.json")
    data = [
        {"ip": "9.9.9.9", "ports": [{"port": 443}]},
        {"ip": "9.9.9.10", "ports": [{"port": 8443}]},
        {"ip": "9.9.9.11", "ports": [{"port": 2053}]},
    ]
    with open(out, "w") as f:
        import json as _j
        _j.dump(data, f)
    return True, 2000.0


def _fake_run_verify(block_index, workdir, cf_scanner_path, proxy=None, workers=200,
                     progress_cb=None):
    """模拟 cf-scanner verify：写 block_NNN_cf.txt（ip,port,colo,cfray,status,conf）。"""
    out = os.path.join(workdir, f"block_{block_index:03d}_cf.txt")
    lines = [
        "ip,port,colo,cfray,status,conf",
        "9.9.9.9,443,SJC,cf-ray-1,200,high",
        "9.9.9.10,8443,LAX,cf-ray-2,200,high",
        "9.9.9.11,2053,ORD,cf-ray-3,200,low",
    ]
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    return True


def _fake_enrich_ips(ip_ports, proxies=None, on_progress=None):
    results = []
    meta = {
        "9.9.9.9": (13335, "United States", "US", "California", "Los Angeles", "Cloudflare, Inc."),
        "9.9.9.10": (45102, "China", "CN", "Guangdong", "Shenzhen", "Alibaba"),
        "9.9.9.11": (4808, "China", "CN", "Beijing", "Beijing", "China Unicom"),
    }
    cf_asns = set()
    try:
        from pipeline.utils import load_cf_official_asns
        cf_asns = load_cf_official_asns()
    except Exception:
        pass
    for ip_port in ip_ports:
        ip = ip_port.rsplit(":", 1)[0]
        asn, country, cc, region, city, org = meta.get(ip, ("-", "-", "-", "-", "-", "-"))
        results.append({
            "ip_port": ip_port,
            "asn": asn,
            "country": country,
            "country_code": cc,
            "region_name": region,
            "city": city,
            "continent": "亚洲/太平洋",
            "country_cn": "中国",
            "flag": "🇨🇳",
            "org": org,
            "is_cf_official": (asn in cf_asns) if isinstance(asn, int) else False,
            "cached_at": "-",
        })
        if on_progress:
            on_progress(len(results))
    return results


def _fake_speedtest_ip(ip, port, sni="cloudflare.com", host="www.cloudflare.com",
                       speed_size=1048576, timeout=5.0, proxy=None,
                       latency_only=False):
    return {"ip_port": f"{ip}:{port}", "latency_ms": 42.0, "download_mbps": 88.5, "error": None}


@pytest.fixture
def patch_all(monkeypatch):
    monkeypatch.setattr(stage1_cidr, "fetch_cidrs", _fake_fetch_cidrs)
    monkeypatch.setattr(stage2_masscan, "run_masscan", _fake_run_masscan)
    monkeypatch.setattr(stage2_masscan, "run_verify", _fake_run_verify)
    monkeypatch.setattr(stage4_enrich, "enrich_ips", _fake_enrich_ips)
    monkeypatch.setattr(stage5_speed, "speedtest_ip", _fake_speedtest_ip)
    monkeypatch.setattr(asnip, "_get_public_ip", lambda: "203.0.113.7")
    # orchestrator 在 __init__ 时找 cf-scanner 二进制，找不到则是 ""，
    # 导致 verify 阶段直接跳过（真实环境需 Go 编译的 cf-scanner）。
    # 模拟时强制认为存在，从而走 verify 分支调用 fake_run_verify。
    from pipeline.orchestrator import Orchestrator
    monkeypatch.setattr(Orchestrator, "_find_cf_scanner", lambda self: "/fake/cf-scanner")
    yield


def _run_pipeline(workdir, asn=13335, ports="443,8443,2053", json_output=False, top_n=None, cidrs=None):
    from pipeline.orchestrator import Orchestrator
    app = Orchestrator(workdir=workdir)
    app.proxies = None
    app.verify_proxy = None
    if cidrs:
        app.run(
            asns=[],
            cidrs=cidrs,
            ports=ports,
            force=False,
            top_n=top_n,
            json_output=json_output,
            speed_top=0,
            rate=2000,
        )
    else:
        app.run(
            asns=[asn],
            ports=ports,
            force=False,
            top_n=top_n,
            json_output=json_output,
            speed_top=0,
            rate=2000,
        )


def test_full_pipeline_runs_and_names_csv(tmp_path, patch_all):
    """全流程跑通，验证输出文件命名 output_{asn}_{时间戳}.csv。"""
    _run_pipeline(str(tmp_path), asn=13335, ports="443,8443,2053")

    files = os.listdir(str(tmp_path))
    csvs = [f for f in files if f.startswith("output_13335_") and f.endswith(".csv")]
    assert csvs, f"未生成 output_13335_*.csv，现有: {files}"

    # 命名格式: output + asn + _ + 时间戳(YYYYMMDD_HHMMSS)
    name = csvs[0]
    m = re.match(r"^output_(\d+)_(\d{8}_\d{6})\.csv$", name)
    assert m, f"文件名格式不符: {name}"
    assert m.group(1) == "13335"
    # 时间戳是 14 位 YYYYMMDD_HHMMSS
    ts = m.group(2)
    time.strptime(ts, "%Y%m%d_%H%M%S")  # 抛错即非法


def test_csv_has_expected_columns_and_rows(tmp_path, patch_all):
    """CSV 列数 = 18，且 CF 官方 AS13335(9.9.9.9) 被正确剔除，剩 2 条。"""
    _run_pipeline(str(tmp_path), asn=13335, ports="443,8443,2053")
    csvs = [f for f in os.listdir(str(tmp_path)) if f.startswith("output_13335_") and f.endswith(".csv")]
    path = os.path.join(str(tmp_path), csvs[0])
    with open(path, encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        rows = list(reader)
    header = rows[0]
    assert len(header) == 14, f"期望 14 列，实际 {len(header)}: {header}"
    # 新 14 列结构：IP地址/端口/TLS/IP位置/地区/城市/大陆/国家(中文)/国旗/延迟/ASN/组织/协议/测速
    assert header[0] == "IP地址" and header[3] == "IP位置"
    assert header[6] == "大陆" and header[7] == "国家(中文)"
    assert header[10] == "ASN号码" and header[12] == "访问协议"
    assert "数据中心" not in header, "数据中心列已删除"
    data_rows = rows[1:]
    # 9.9.9.9 是 Cloudflare 官方 ASN 13335 → 被剔除；剩 2 条
    assert len(data_rows) == 2, f"期望 2 条（剔除 CF 官方后），实际: {data_rows}"
    ips = {r[0] for r in data_rows}
    assert ips == {"9.9.9.10", "9.9.9.11"}, ips


def test_cf_official_asn_is_filtered(tmp_path, patch_all):
    """专门验证：CF 官方 ASN 的 IP 不会出现在最终结果（黑名单生效）。"""
    _run_pipeline(str(tmp_path), asn=13335, ports="443,8443,2053")
    csvs = [f for f in os.listdir(str(tmp_path)) if f.startswith("output_13335_") and f.endswith(".csv")]
    path = os.path.join(str(tmp_path), csvs[0])
    with open(path, encoding="utf-8") as f:
        content = f.read()
    assert "9.9.9.9" not in content, "CF 官方 IP 9.9.9.9 不应出现在结果中"
    assert "9.9.9.10" in content and "9.9.9.11" in content


def test_json_output_generated(tmp_path, patch_all):
    """--json 时生成同名 .json。"""
    _run_pipeline(str(tmp_path), asn=13335, ports="443,8443,2053", json_output=True)
    files = os.listdir(str(tmp_path))
    jsons = [f for f in files if f.startswith("output_13335_") and f.endswith(".json")]
    assert jsons, f"未生成 output_13335_*.json，现有: {files}"
    path = os.path.join(str(tmp_path), jsons[0])
    import json
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list) and len(data) >= 1
    assert "ip" in data[0] and "protocol" in data[0]


def test_http_server_serves_csv(tmp_path, patch_all):
    """HTTP 下载服务返回真实产出的 CSV，且 Content-Disposition 为附件。"""
    _run_pipeline(str(tmp_path), asn=13335, ports="443,8443,2053")

    csvs = sorted(glob.glob(os.path.join(str(tmp_path), "output_*.csv")),
                  key=os.path.getmtime)
    assert csvs
    report = os.path.join(str(tmp_path), "report.csv")
    shutil.copy2(csvs[-1], report)

    # SimpleHTTPRequestHandler 以 cwd 为根，切到 tmp_path
    cwd = os.getcwd()
    os.chdir(str(tmp_path))
    from http.server import HTTPServer, SimpleHTTPRequestHandler
    try:
        srv = HTTPServer(("127.0.0.1", 0), SimpleHTTPRequestHandler)
        port = srv.server_address[1]
        import threading
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{port}/report.csv"
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read().decode("utf-8")
                assert resp.status == 200
                assert "IP地址" in body, "HTTP 返回的 CSV 缺少表头"
                assert "9.9.9.10" in body or "9.9.9.11" in body
        finally:
            srv.shutdown()
    finally:
        os.chdir(cwd)


def test_top_n_limits_rows(tmp_path, patch_all):
    """--top 限制最终输出条数。"""
    _run_pipeline(str(tmp_path), asn=13335, ports="443,8443,2053", top_n=1)
    csvs = [f for f in os.listdir(str(tmp_path)) if f.startswith("output_13335_") and f.endswith(".csv")]
    path = os.path.join(str(tmp_path), csvs[0])
    with open(path, encoding="utf-8") as f:
        rows = list(csv.reader(f))
    # 表头 + 最多 top_n 条
    assert len(rows) - 1 <= 1, f"--top 1 应最多 1 条数据，实际 {len(rows)-1}"


def test_cidr_input_runs_and_names_csv(tmp_path, patch_all):
    """直接扫 IP 段：跳过 ASN→CIDR 拉取，输出文件名用 CIDR 主段。"""
    _run_pipeline(str(tmp_path), cidrs=["45.221.113.0/24", "45.221.114.0/24"])

    files = os.listdir(str(tmp_path))
    csvs = [f for f in files if f.startswith("output_45.221.113.0_24_") and f.endswith(".csv")]
    assert csvs, f"未生成 CIDR 命名 output_45.221.113.0_24_*.csv，现有: {files}"

    # CIDR 模式下不生成 ASN 前缀文件
    assert not any(f.startswith("output_13335_") for f in files), "不应生成 ASN 前缀文件"

    # CSV 内容正常（14 列 + 数据行）
    path = os.path.join(str(tmp_path), csvs[0])
    with open(path, encoding="utf-8-sig") as f:
        rows = list(csv.reader(f))
    assert len(rows[0]) == 14, f"期望 14 列，实际 {len(rows[0])}"
    assert len(rows) - 1 >= 1, "CIDR 扫描应有数据行"


def test_mixed_asn_cidr_rejected(tmp_path, monkeypatch):
    """混合输入（ASN+CIDR）应被输入层拒绝，不进入管线。"""
    import io
    from asnip import cmd_scan
    class _Args:
        asn = ["13335,45.221.113.0/24"]
        ports = "443"
        top = None
        json = False
        daemon = False
        force = False
        rate = 2000
        no_deps = True
        progress_port = 8082
        port = 8081
        public_ip = None
    # 拦截 input / 打印，只验证混合输入路径返回
    monkeypatch.setattr("builtins.input", lambda *a, **k: "y")
    captured = io.StringIO()
    monkeypatch.setattr("sys.stdout", captured)
    cmd_scan(_Args())
    out = captured.getvalue()
    assert "不支持 ASN 和 IP 段混合输入" in out, f"应拒绝混合输入，实际: {out}"
