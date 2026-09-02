#!/usr/bin/env python3
"""验证 progress.py 与 progress_server.py 使用同一默认进度文件 + 剩余时间估算。"""
import json, os, sys, time

PROJECT = r"C:\Users\12155\projects\ASNIPtest-optimized"
sys.path.insert(0, PROJECT)

import pipeline.progress as P
import progress_server as PS

# 确认两者默认路径一致（真实运行时结论）
print("=== 路径一致性 ===")
print(f"  progress.py    PROGRESS_FILE: {P.PROGRESS_FILE}")
print(f"  progress_server PROGRESS_FILE: {PS.PROGRESS_FILE}")
assert os.path.abspath(P.PROGRESS_FILE) == os.path.abspath(PS.PROGRESS_FILE), "路径不一致!"
print("  ✅ 两个模块使用同一进度文件")

# 用 progress.py 写一个"运行中"状态（不覆盖路径，走默认）
P.reset()
P.stage("masscan", asn=["36002"], ports="443,8443", rate=5000)
# 模拟已跑120s，34/100
st = json.load(open(P.PROGRESS_FILE, encoding="utf-8"))
st["stage_start"] = time.time() - 120
st["masscan"] = {"done": 34, "total": 100, "found": 456, "status": "running"}
json.dump(st, open(P.PROGRESS_FILE, "w", encoding="utf-8"))

# progress_server 读取
state = PS._load_progress()
print("\n=== 剩余时间估算 ===")
print(f"  running: {state.get('running')}, stage: {state.get('stage')}")
print(f"  masscan: {state['masscan']['done']}/{state['masscan']['total']}, 已跑120s")
rem = PS._estimate_remaining(state)
print(f"  预计剩余: {PS._format_duration(rem)}")
# 34/100 的比例，120s → 总约353s，剩余约233s
assert rem and rem > 180, f"剩余时间异常: {rem}"
print("  ✅ 剩余时间估算合理 (~233s)")

# 阶段名检查
print("  stage_name:", state.get("stage_name"))

# 清理
os.remove(P.PROGRESS_FILE)
print("\n✅ 路径一致性 + 剩余时间测试通过")
