"""② masscan 端口发现 + verify 调度。

核心职责：
  - 生成 scan_plan.json（一次性全量规划）
  - 逐块跑 masscan
  - 调用 cf-scanner（Go）验证
  - IP:Port 级 Resume
  - 水位/背压
"""
import os
import re
import shutil
import subprocess
import sys
import time
import threading
from pathlib import Path

from .utils import ensure_dirs, CACHE_DIR

# 默认 CF 加密端口
DEFAULT_PORTS = "443,8443,2053,2083,2087,2096"

# Schema 版本（占位）
SCAN_SCHEMA = 1
VERIFY_SCHEMA = 1
RESUME_SCHEMA = 1


def make_ports_hash(ports_str: str) -> str:
    """端口集标准化 SHA256。"""
    # 先按逗号分割、排序
    parts = sorted(p.strip() for p in ports_str.split(",") if p.strip())
    canonical = ",".join(parts)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def generate_plan(asn: int, prefixes: list[str], ports: str = DEFAULT_PORTS,
                  block_size: int = 500) -> dict:
    """生成 scan_plan.json（一次性全量规划）。"""
    # 确定 block 划分（纯输入驱动，不依赖运行时）
    blocks = []
    for i in range(0, len(prefixes), block_size):
        chunk = prefixes[i:i + block_size]
        idx = len(blocks) + 1
        cidrs_content = "\n".join(chunk) + "\n"
        cidr_hash = hashlib.sha256(cidrs_content.encode()).hexdigest()[:16]
        blocks.append({
            "index": idx,
            "cidr_range": {"start_idx": i, "end_idx": min(i + block_size, len(prefixes))},
            "block_input_hash": cidr_hash,
            "cidrs_file": f"block_{idx:03d}_cidrs.txt",
        })

    plan = {
        "resume_identity": {
            "asn": str(asn),
            "ports_hash": make_ports_hash(ports),
            "verify_method": "hybrid",
            "scan_schema": SCAN_SCHEMA,
            "verify_schema": VERIFY_SCHEMA,
            "resume_schema": RESUME_SCHEMA,
            "blocks": blocks,
        },
        "runtime_info": {
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "tool_version": "1.0.0",
            "total_blocks": len(blocks),
        },
    }
    return plan


def materialize_plan(plan: dict, workdir: str) -> str:
    """将 Plan 写到磁盘：先 scan_plan.json，再逐 block 写 cidrs 文件。

    返回 scan_plan.json 路径。
    """
    os.makedirs(workdir, exist_ok=True)

    # 先算 plan_hash（含所有 blocks 信息）
    identity = plan["resume_identity"]
    identity_str = json.dumps(identity, sort_keys=True)
    plan["resume_identity"]["plan_hash"] = hashlib.sha256(
        identity_str.encode()
    ).hexdigest()[:16]

    # 原子写 scan_plan.json
    plan_path = os.path.join(workdir, "scan_plan.json")
    tmp_path = plan_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(plan, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, plan_path)

    # 写各 block CIDR 文件
    for blk in identity["blocks"]:
        cidrs_file = os.path.join(workdir, blk["cidrs_file"])
        start, end = blk["cidr_range"]["start_idx"], blk["cidr_range"]["end_idx"]
        # 从原始 prefixes 重建（无法从 plan 重建，需调用方传递）
        # 实际使用中由 Orchestrator 调用并传入 prefixes
        # 这里只写空占位，内容由调用方填充
        Path(cidrs_file).touch()

    return plan_path


def get_block_status(workdir: str, plan: dict) -> list[dict]:
    """检查每个 block 的状态：未开始/需重验/已完成。"""
    blocks = plan["resume_identity"]["blocks"]
    statuses = []
    for blk in blocks:
        cf_txt = os.path.join(workdir, f"block_{blk['index']:03d}_cf.txt")
        cf_tmp = os.path.join(workdir, f"block_{blk['index']:03d}_cf.tmp")
        json_file = os.path.join(workdir, f"block_{blk['index']:03d}.json")

        has_json = os.path.exists(json_file) and os.path.getsize(json_file) > 0
        has_cf = os.path.exists(cf_txt)
        has_cf_tmp = os.path.exists(cf_tmp)

        if has_cf:
            state = "done"
        elif has_json and not has_cf:
            state = "verify_only"  # masscan 已跑完，只需重验
        elif has_cf_tmp:
            state = "verify_partial"  # 上次验到一半
        else:
            state = "pending"  # 需重扫

        statuses.append({
            "index": blk["index"],
            "state": state,
            "cidrs_file": blk["cidrs_file"],
        })
    return statuses


def run_masscan(block_index: int, cidrs_file: str, ports: str,
                workdir: str, rate: int = 2000) -> bool:
    """跑 masscan 扫描一个 block。

    输出: workdir/block_NNN.json.tmp → (成功) os.replace → block_NNN.json
    """
    cidrs_path = os.path.join(workdir, cidrs_file)
    if not os.path.exists(cidrs_path) or os.path.getsize(cidrs_path) == 0:
        print(f"  ⚠ Block {block_index}: CIDR 文件为空，跳过")
        return False

    out_tmp = os.path.join(workdir, f"block_{block_index:03d}.json.tmp")
    out_final = os.path.join(workdir, f"block_{block_index:03d}.json")
    targets_tmp = os.path.join(workdir, f"block_{block_index:03d}_targets.txt.tmp")
    targets_file = os.path.join(workdir, f"block_{block_index:03d}_targets.txt")

    # 预先建立合法空 JSON，避免流式读取时报错
    with open(out_tmp, "w") as f:
        f.write("[]\n")

    cmd = [
        "masscan",
        "-iL", cidrs_path,
        "-p", ports,
        "--rate", str(rate),
        "-oJ", out_tmp,
        "--wait", "5",
        "--max-retries", "1",
    ]

    print(f"  🚀 Block {block_index}: masscan {ports} rate={rate}")
    start = time.time()

    # 基于输出文件行数计算 m/n 进度
    if os.path.exists(cidrs_path):
        with open(cidrs_path) as f:
            lines = [l.strip() for l in f if l.strip()]
        total_targets = len(lines)
    else:
        total_targets = 0

    # 仅在实际发现端口数变化时更新显示，避免刷屏
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    last_found = ""
    _seen = set()
    append_lock = threading.Lock()
    try:
        with open(targets_tmp, "w") as _f_tmp:
            with open(out_tmp, "w") as _f_json:
                for line in proc.stdout:
                    _f_json.write(line)
                    _f_json.flush()
                    line = line.rstrip()
                    try:
                        obj = json.loads(line)
                        for entry in obj:
                            ip = entry.get("ip")
                            if not ip:
                                continue
                            for p in entry.get("ports", []):
                                port = p.get("port")
                                if port:
                                    key = f"{ip}:{port}"
                                    with append_lock:
                                        if key not in _seen:
                                            _seen.add(key)
                                            _f_tmp.write(f"{ip}:{port}\n")
                                            _f_tmp.flush()
                    except Exception:
                        pass
                    m = re.search(r"rate:\s+([0-9.]+)-kpps.*found=(\d+)", line)
                    if m:
                        rate_str = m.group(1).strip()
                        found_str = m.group(2).strip()
                        done_targets = sum(1 for l in open(targets_tmp) if l.strip()) if os.path.exists(targets_tmp) else 0
                        block_str = ""
                        if total_targets > 0:
                            block_pct = min(done_targets / total_targets, 1.0)
                            block_str = f"  block={block_pct*100:.0f}%"
                        display = f"\r  ⏳ 命中={found_str}{block_str}  速率={rate_str}-kpps"
                        display = display.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
                        if found_str != last_found:
                            sys.stdout.write(display)
                            sys.stdout.flush()
                            last_found = found_str
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("\n  已取消扫描")
        return False
    proc.wait()
    sys.stdout.write("\n")
    sys.stdout.flush()

    elapsed = time.time() - start
    if proc.returncode != 0:
        print(f"  ✗ Block {block_index}: masscan 失败 (rc={proc.returncode})")
        return False

    # 检查输出文件
    if not os.path.exists(out_tmp) or os.path.getsize(out_tmp) < 10:
        print(f"  ℹ Block {block_index}: 无开放端口 (空结果)")
        # 写空文件防 Resume 死循环
        with open(out_tmp, "w") as f:
            f.write("[]")
        os.replace(out_tmp, out_final)
        print(f"  ✅ Block {block_index}: 完成 ({elapsed:.1f}s, 0 开放端口)")
        return True

    os.replace(out_tmp, out_final)
    # 统计开放端口数
    import json as j
    with open(out_final) as f:
        try:
            entries = j.load(f)
            count = len(entries)
        except Exception:
            count = 0
    print(f"  ✅ Block {block_index}: 完成 ({elapsed:.1f}s, {count} 开放端口)")
    return True


def run_verify(block_index: int, workdir: str, cf_scanner_path: str,
               proxy: str | None = None, workers: int = 200) -> bool:
    """对 block 的 masscan 结果调用 cf-scanner 验证。

    输出: workdir/block_NNN_cf.txt
    """
    json_file = os.path.join(workdir, f"block_{block_index:03d}.json")
    if not os.path.exists(json_file):
        print(f"  ⚠ Block {block_index}: 无 masscan 结果，跳过验证")
        return False

    out_txt = os.path.join(workdir, f"block_{block_index:03d}_cf.txt")

    # subprocess 不搜索当前目录，必须用绝对路径
    cf_scanner_abs = os.path.abspath(cf_scanner_path)

    # cf-scanner 要的输入是「每行 IP:port」纯文本，不是 masscan JSON
    # 优先使用流式生成的 targets_tmp（断点续跑核心），回退到批量提取
    targets_file = os.path.join(workdir, f"block_{block_index:03d}_targets.txt")
    targets_tmp = os.path.join(workdir, f"block_{block_index:03d}_targets.txt.tmp")
    if os.path.exists(targets_tmp) and os.path.getsize(targets_tmp) > 0:
        shutil.copyfile(targets_tmp, targets_file)
        print(f"  ⏩ Block {block_index}: 使用流式缓存 targets ({sum(1 for _ in open(targets_file))} 条)")
    else:
        _extract_targets_from_masscan(json_file, targets_file)
    if os.path.getsize(targets_file) == 0:
        # 没有开放端口，直接写空结果
        with open(out_txt, "w") as f:
            f.write("ip,port,colo,cfray,status,conf\n")
        print(f"  ℹ Block {block_index}: 无开放端口，跳过验证")
        return True

    cmd = [
        cf_scanner_abs,
        "-i", targets_file,
        "-o", out_txt,
        "-c", str(workers),
        "-timeout", "10s",
        "-connect-timeout", "5s",
    ]
    if proxy:
        cmd += ["-proxy", proxy]

    print(f"  🔍 Block {block_index}: cf-scanner 验证 (workers={workers})")
    start = time.time()

    # 基于输出文件行数实时展示验证进度
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    total_targets = sum(1 for _ in open(targets_file, "r")) if os.path.exists(targets_file) else 0
    last_count = 0
    last_err = ""

    # 定期刷新进度
    import time as _time
    try:
        while proc.poll() is None:
            if os.path.exists(out_txt):
                with open(out_txt, "r") as f:
                    lines = f.readlines()
                count = sum(1 for l in lines if l.strip() and not l.startswith("ip,"))
                if count != last_count:
                    pct = count / total_targets if total_targets else 0
                    bar = "█" * int(24 * pct) + " " * (24 - int(24 * pct))
                    sys.stdout.write(f"\r  ⏳ 验证: {count}/{total_targets} ({pct*100:.0f}%) |{bar}|")
                    sys.stdout.flush()
                    last_count = count
            # 非阻塞读 stderr
            if proc.stdout:
                line = proc.stdout.readline()
                if line:
                    line = line.rstrip()
                    if line and line != last_err:
                        sys.stdout.write(f"\n  ⚠ {line[:100]}\n")
                        sys.stdout.flush()
                        last_err = line
            _time.sleep(0.1)
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("\n  已取消验证")
        return False
    proc.wait()

    # 最终进度
    if os.path.exists(out_txt):
        with open(out_txt, "r") as f:
            lines = f.readlines()
        final_count = sum(1 for l in lines if l.strip() and not l.startswith("ip,"))
        pct = final_count / total_targets if total_targets else 0
        bar = "█" * int(24 * pct) + " " * (24 - int(24 * pct))
        sys.stdout.write(f"\r  ✅ 验证完成: {final_count}/{total_targets} ({pct*100:.0f}%) |{bar}|\n")
        sys.stdout.flush()
    else:
        print("  ?? Block {block_index}: 验证未生成输出")

    elapsed = time.time() - start
    if proc.returncode != 0:
        print(f"  ✗ Block {block_index}: cf-scanner 失败 (rc={proc.returncode})")
        return False

    if os.path.exists(out_txt) and os.path.getsize(out_txt) > 0:
        line_count = 0
        with open(out_txt) as f:
            # 统计非空非表头的行数
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("ip,"):
                    line_count += 1
        if line_count > 0:
            print(f"  ✅ Block {block_index}: 验证完成 ({elapsed:.1f}s, {line_count} 条)")
        else:
            print(f"  ℹ Block {block_index}: 验证完成，无命中")
    else:
        print(f"  ℹ Block {block_index}: 验证完成，无命中")
    return True


def _extract_targets_from_masscan(json_file: str, targets_file: str):
    """从 masscan 的 JSON 输出提取 ip:port 列表，写入 targets_file（每行一个）。

    masscan JSON 格式: [{"ip": "1.2.3.4", "ports": [{"port": 443, ...}]}, ...]
    空结果可能是 "[]" 或缺失。
    """
    import json as _json

    targets = []
    try:
        with open(json_file) as f:
            content = f.read().strip()
        if not content or content == "[]":
            pass
        else:
            data = _json.loads(content)
            for entry in data:
                ip = entry.get("ip")
                if not ip:
                    continue
                for p in entry.get("ports", []):
                    port = p.get("port")
                    if port:
                        targets.append(f"{ip}:{port}")
    except Exception:
        # 解析失败就用空列表
        targets = []

    with open(targets_file, "w") as f:
        if targets:
            f.write("\n".join(targets) + "\n")
