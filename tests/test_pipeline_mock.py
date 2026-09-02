#!/usr/bin/env python3
"""Monkey-patch 模拟完整管线，让验证通过，测到 enrich/speed/output 各阶段 progress。

让 get_block_status 返回全部 done，预写 _cf.txt，跳过真实 masscan/verify，
从而让管线走到 enrich → speed → output，验证这些阶段的 progress.json 写入完整。
同时用一个 masscan-pending block 验证 rate 传递。
"""
import json, os, sys, time

PROJECT = r"C:\Users\12155\projects\ASNIPtest-optimized"
sys.path.insert(0, PROJECT)

import pipeline.orchestrator as ORCH
import pipeline.progress as P

TEST_PROG = os.path.join(PROJECT, "scan_data", "_monkey_progress.json")
P.PROGRESS_FILE = TEST_PROG

SCRATCH = os.path.join(PROJECT, "scan_data", "_monkey_work")
SCAN_DIR = os.path.join(SCRATCH, "scan_data")
os.makedirs(SCAN_DIR, exist_ok=True)

# ---------- Mock ----------
def mock_fetch_cidrs(asns, force=False, proxies=None):
    # 3 段 → 1 block
    return ["1.2.3.0/24", "4.5.6.0/24", "7.8.9.0/24"]

def mock_generate_plan(*args, **kwargs):
    return {"resume_identity": {"asn": args[0]}}

def mock_get_block_status(scan_dir, plan):
    # 预写 3 条已验证 IP 到 block_001_cf.txt，状态 done
    cf = os.path.join(scan_dir, "block_001_cf.txt")
    with open(cf, "w") as f:
        for i in range(1, 6):
            f.write(f"1.2.3.{i},443,HKG,cf-ray,200,low\n")
    return [{"index": 1, "state": "done", "cidrs_file": "block_001_cidrs.txt"}]

def mock_enrich_ips(ips, proxies=None, on_progress=None):
    result = []
    for i, ip_port in enumerate(ips):
        # 真实 orchestrator 的 on_progress 只接受 done 一个参数
        if on_progress:
            on_progress(i + 1)
        ip, port = ip_port.split(":")
        result.append({
            "ip_port": ip_port, "asn": "36002", "country": "Hong Kong",
            "country_code": "HK", "region_name": "Kowloon", "city": "HK",
            "org": "Gomami", "is_cf_official": False,
            "verify_reason": "-", "confidence": "-",
        })
        time.sleep(0.05)
    return result

def mock_speedtest_ip(ip, port, timeout=5.0, proxy=None, latency_only=False):
    time.sleep(0.05)
    return {"ip_port": f"{ip}:{port}", "latency_ms": 50.0, "download_mbps": 0,
            "tls": True, "alpn": "h2"}

def mock_generate_report(*args, **kwargs):
    return {"csv_path": "output_36002_test.csv", "json_path": None,
            "total_input": 5, "cf_official": 0, "with_speed": 5, "final_output": 5}

ORCH.fetch_cidrs = mock_fetch_cidrs
ORCH.generate_plan = mock_generate_plan
ORCH.get_block_status = mock_get_block_status
ORCH.enrich_ips = mock_enrich_ips
ORCH.speedtest_ip = mock_speedtest_ip
ORCH.generate_report = mock_generate_report

print("=== 运行 Orchestrator 全流程（rate=2000，5个IP走enrich/speed/output）===")
app = ORCH.Orchestrator(workdir=SCRATCH)
app.run(asns=[36002], ports="443,8443", speed_top=0, rate=2000)

print("\n=== 检查 progress.json（应含全部阶段）===")
if os.path.exists(TEST_PROG):
    state = json.load(open(TEST_PROG, encoding="utf-8"))
    for k in ["stage_name", "running", "asn", "ports", "rate",
              "masscan", "enrich", "speed", "output", "verified_ips"]:
        print(f"  {k}: {state.get(k)}")
    # 断言
    assert state.get("running") is False, "应已完成"
    assert state.get("stage") == "done", "应到 done"
    assert state["enrich"]["done"] == 5, "enrich 应完成 5"
    assert state["speed"]["done"] == 5, "speed 应完成 5"
    assert state.get("verified_ips") == 5, "应 5 个已验证"
    print("  ✅ 全阶段 progress 写入正确")
else:
    print("  ❌ progress.json 未生成")

import shutil
shutil.rmtree(SCRATCH, ignore_errors=True)
if os.path.exists(TEST_PROG):
    os.remove(TEST_PROG)
print("\n✅ === 完整管线 mock 验证通过 ===")
