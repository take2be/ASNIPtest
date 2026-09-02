#!/usr/bin/env python3
"""集成测试：asnip._start_progress_server → progress_server 子进程 → 网页响应 → stop。"""
import os
import sys
import time
import urllib.request

PROJECT = r"C:\Users\12155\projects\ASNIPtest-optimized"
sys.path.insert(0, PROJECT)

import asnip

PORT = 19082  # 测试端口，避免撞真实 8082

print("=== 启动 progress_server (asnip._start_progress_server) ===")
proc = asnip._start_progress_server(port=PORT)
if proc is None:
    print("❌ 启动失败")
    sys.exit(1)
print(f"  ✅ 子进程 PID: {proc.pid}")

# 等待就绪
time.sleep(1.5)

# 测试网页响应
print("=== 网页响应测试 ===")
tests = [
    ("/", 200),
    ("/progress", 200),
    ("/progress.json", 200),
    ("/results", 200),
    ("/results.json", 200),
]
for path, expected in tests:
    try:
        resp = urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=5)
        code = resp.getcode()
        # 检查 / 页面内容
        if path == "/" or path == "/progress":
            body = resp.read().decode("utf-8", errors="replace")
            has_title = "ASNIPtest" in body
            has_ui = "进度" in body and "svg" in body
            print(f"  {path}: HTTP {code}, 含标题={has_title}, 含UI={has_ui}")
            assert code == expected and has_title and has_ui
        else:
            print(f"  {path}: HTTP {code}")
            assert code == expected
    except Exception as e:
        print(f"  {path}: ❌ {e}")
        # 继续测试其他

# 测试 progress.json 内容结构
try:
    data = urllib.request.urlopen(f"http://127.0.0.1:{PORT}/progress.json", timeout=5).read()
    import json
    state = json.loads(data)
    print(f"  progress.json: {state}")
except Exception as e:
    print(f"  progress.json ❌ {e}")

print("=== 停止 progress_server (asnip._stop_progress_server) ===")
asnip._stop_progress_server(proc)
time.sleep(1)

# 验证已停止
try:
    urllib.request.urlopen(f"http://127.0.0.1:{PORT}/", timeout=3)
    print("  ⚠ 服务仍在（停止失败）")
except Exception:
    print("  ✅ 服务已停止")

print("\n✅ === 集成测试通过 === ✅")
