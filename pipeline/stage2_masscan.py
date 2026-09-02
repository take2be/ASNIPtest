"""② masscan 端口发现 + verify 调度。

核心职责：
  - 生成 scan_plan.json（一次性全量规划）
  - 逐块跑 masscan
  - 调用 cf-scanner（Go）验证
  - IP:Port 级 Resume
  - 水位/背压
"""
import hashlib
import json
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

# 增量提取 masscan -oJ 结果用的预编译正则（每秒调用，避免重复编译）
_RE_JSON_IP = re.compile(r'"ip"\s*:\s*"([^"]+)"')
_RE_JSON_PORT = re.compile(r'"port"\s*:\s*(\d+)')


def _iter_targets_from_text(text: str):
    """从一段 masscan JSON 文本中按记录边界产出 ip:port。

    不依赖"每条记录独占一行"——masscan -oJ 实际是一行一条，
    但 json.dumps 等来源可能把整个数组压成一行。
    做法：定位每个 "ip" 键，该记录的 ports 就在本次 "ip" 与下一个 "ip" 之间，
    这样嵌套的 ports 数组也不会串到上一条或下一条。
    """
    ips = list(_RE_JSON_IP.finditer(text))
    for i, m in enumerate(ips):
        ip = m.group(1)
        end = ips[i + 1].start() if i + 1 < len(ips) else len(text)
        for pm in _RE_JSON_PORT.finditer(text, m.end(), end):
            yield f"{ip}:{pm.group(1)}"


def make_ports_hash(ports_str: str) -> str:
    """端口集标准化 SHA256。"""
    # 先按逗号分割、排序
    parts = sorted(p.strip() for p in ports_str.split(",") if p.strip())
    canonical = ",".join(parts)
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def generate_plan(asn: int, prefixes: list[str], ports: str = DEFAULT_PORTS,
                  block_size: int = 50) -> dict:
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


def materialize_plan(plan: dict, workdir: str, prefixes: list[str] | None = None) -> str:
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
    if prefixes:
        for blk in identity["blocks"]:
            cidrs_file = os.path.join(workdir, blk["cidrs_file"])
            start, end = blk["cidr_range"]["start_idx"], blk["cidr_range"]["end_idx"]
            chunk = prefixes[start:end]
            with open(cidrs_file, "w") as f:
                f.write("\n".join(chunk) + "\n")
    else:
        # 如果没有 prefixes，写空占位（Resume 场景从已有文件续跑）
        for blk in identity["blocks"]:
            cidrs_file = os.path.join(workdir, blk["cidrs_file"])
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
                workdir: str, rate: int = 2000) -> tuple[bool, float]:
    """跑 masscan 扫描一个 block。

    返回: (success: bool, actual_kpps: float)
    actual_kpps 是 block 结束时 masscan 报告的实际 kpps，供调用方做 rate 自适应。
    """
    cidrs_path = os.path.join(workdir, cidrs_file)
    if not os.path.exists(cidrs_path) or os.path.getsize(cidrs_path) == 0:
        print(f"  ⚠ Block {block_index}: CIDR 文件为空，跳过")
        return False, 0.0

    out_tmp = os.path.join(workdir, f"block_{block_index:03d}.json.tmp")
    out_final = os.path.join(workdir, f"block_{block_index:03d}.json")
    targets_tmp = os.path.join(workdir, f"block_{block_index:03d}_targets.txt.tmp")
    targets_file = os.path.join(workdir, f"block_{block_index:03d}_targets.txt")


    cmd = [
        "masscan",
        "-iL", cidrs_path,
        "-p", ports,
        "--rate", str(rate),
        "-oJ", out_tmp,
        "--wait", "5",
        "--max-retries", "3",
        "--randomize-hosts",
    ]

    print(f"  🚀 Block {block_index}: masscan {ports} rate={rate}")
    start = time.time()

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    last_found = ""
    _last_shown_pct = -1
    _seen = set()
    append_lock = threading.Lock()
    actual_kpps = 0.0
    _json_offset = [0]   # 增量提取的字节偏移（内存恒定，不随文件增长）
    poll_time = time.time()
    try:
        with open(targets_tmp, "w") as _f_tmp:
            for line in proc.stdout:
                line = line.rstrip()
                m = re.search(r"rate:\s*([0-9.]+)-kpps,\s*([0-9.]+)%\s+done", line)
                _fm = re.search(r"found=(\d+)", line)
                if m:
                    rate_str = m.group(1).strip()
                    done_str = m.group(2).strip()
                    found_str = (_fm.group(1) if _fm else "?").strip()
                    try:
                        actual_kpps = float(rate_str)
                        # 实时写入进度（面板显示扫描速率 + S2 实时进度）
                        try:
                            from . import progress as _p
                            _p.update_rate(actual_kpps)
                            _p.update_masscan_progress(float(done_str), found_str)
                            # 实时日志：每 1% 写一条（masscan 每秒输出，1% 一跳即实时）
                            _cur = int(float(done_str))
                            _last = _p.get_block_log_pct()
                            if _cur != _last:
                                _p.set_block_log_pct(_cur)
                                _p.log(f"Block {block_index} 扫描中 {_cur}% 命中={found_str} 速率={rate_str} kpps")
                        except Exception:
                            pass
                    except ValueError:
                        pass
                    display = f"\r  ⏳ {done_str}%  命中={found_str}  速率={rate_str}-kpps"
                    display = display.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
                    # 进度行每次解析都刷新（不能只在命中数变化时刷新——命中数可能长时间不变，导致终端进度停留在旧值）
                    _cur_pct = int(float(done_str))
                    if found_str != last_found or _cur_pct != _last_shown_pct:
                        sys.stdout.write(display)
                        sys.stdout.flush()
                        last_found = found_str
                        _last_shown_pct = _cur_pct
                now = time.time()
                if now - poll_time >= 1.0:
                    poll_time = now
                    # 按字节偏移增量消费，无需先比对文件大小
                    _extract_new_targets(out_tmp, _f_tmp, _seen, _json_offset, append_lock)
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("\n  已取消扫描")
        return False, 0.0
    finally:
        # 无论正常结束、异常还是被上层中断，都不留 masscan 孤儿进程
        # （父进程被 OOM kill 后 masscan 仍会继续跑、继续写盘、持有已删文件句柄）
        if proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
            except Exception:
                pass
    proc.wait()
    sys.stdout.write("\n")
    sys.stdout.flush()

    elapsed = time.time() - start
    if proc.returncode != 0:
        print(f"  ✗ Block {block_index}: masscan 失败 (rc={proc.returncode})")
        return False, actual_kpps

    # 检查输出文件
    if not os.path.exists(out_tmp) or os.path.getsize(out_tmp) == 0:
        print(f"  ℹ Block {block_index}: 无开放端口 (空结果)")
        # 写空文件防 Resume 死循环
        with open(out_tmp, "w") as f:
            f.write("[]")
        os.replace(out_tmp, out_final)
        print(f"  ✅ Block {block_index}: 完成 ({elapsed:.1f}s, 0 开放端口)")
        return True, actual_kpps

    os.replace(out_tmp, out_final)
    # 统计开放端口数：逐行计数（结果文件可达 GB 级，不能 json.load 全量读）
    count = 0
    try:
        with open(out_final, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if len(line) >= 8 and _RE_JSON_IP.search(line):
                    count += 1
    except Exception:
        count = 0
    # 兜底：进度行没解析到 kpps 时，用 输出行数/耗时 估算实际速率
    if actual_kpps <= 0 and elapsed > 0:
        actual_kpps = round(count / elapsed, 2)
        try:
            from . import progress as _p
            _p.update_rate(actual_kpps)
        except Exception:
            pass
    print(f"  ✅ Block {block_index}: 完成 ({elapsed:.1f}s, {count} 开放端口, {actual_kpps:.1f} kpps)")
    return True, actual_kpps


def run_verify(block_index: int, workdir: str, cf_scanner_path: str,
               proxy: str | None = None, workers: int = 200,
               progress_cb=None) -> bool:
    """对 block 的 masscan 结果调用 cf-scanner 验证。

    输出: workdir/block_NNN_cf.txt
    progress_cb: 可选回调 (done, total, hits)，每秒解析到进度行时调用（供面板实时显示）
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
        "--backpressure",
        "--state", out_txt + ".tmp.state",
    ]
    if proxy:
        cmd += ["-proxy", proxy]

    print(f"  🔍 Block {block_index}: cf-scanner 验证 (workers={workers})")
    start = time.time()

    # 验证进度 — 单行显示（同 masscan block 逻辑）
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    total_targets = sum(1 for _ in open(targets_file, "r")) if os.path.exists(targets_file) else 0
    last_display = ""

    import time as _time
    try:
        while proc.poll() is None:
            if proc.stdout:
                line = proc.stdout.readline()
                if line:
                    line = line.rstrip()
                    if not line:
                        continue
                    # 解析 cf-scanner 进度行:
                    #   "Scanned X/Y (Z%) | R/s | hits=N"
                    # 必须捕获真实已扫数量 X（不能用百分比反推：Z 带小数，
                    # 且 int("10.0") 会抛 ValueError 被吞掉 → 面板 S3 永远 0%）
                    m = re.search(
                        r"Scanned\s+(\d+)/(\d+)\s+\(([0-9.]+)%\)\s+\|\s+(\d+)/s\s+\|\s+hits=(\d+)",
                        line,
                    )
                    if m:
                        scanned_s, total_s, pct, rate, hits = m.groups()
                        display = "\r  ⏳ 验证: %s%% | %s/s | hits=%s" % (pct, rate, hits)
                        if display != last_display:
                            sys.stdout.write(display)
                            sys.stdout.flush()
                            last_display = display
                        # 实时写入面板进度（S3 真实验证进度）
                        if progress_cb:
                            try:
                                _scanned = int(scanned_s)
                                _tot = int(total_s) or total_targets
                                progress_cb(min(_scanned, _tot), _tot, int(hits))
                            except Exception:
                                pass
                    else:
                        # 非进度行（初始信息/错误等）→ 去重打印
                        if line != last_display:
                            sys.stdout.write(f"\n  ⚠ {line[:100]}\n")
                            sys.stdout.flush()
                            last_display = line
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

    masscan JSON 每条记录独占一行: {"ip": "1.2.3.4", ..., "ports": [{"port": 443, ...}]},
    空结果可能是 "[]" 或缺失。

    逐块流式解析 + 边读边写：结果文件可达 GB 级（全端口大 ASN 命中数百万条），
    绝不能 f.read() 整个读进内存再 json.loads（会 OOM）。
    按 8MB 分块读，块尾不完整的记录留到下一块，兼容"整个数组压成一行"的输入。
    """
    seen = set()
    count = 0
    CHUNK = 8 * 1024 * 1024
    try:
        with open(json_file, "r", encoding="utf-8", errors="replace") as fin, \
             open(targets_file, "w") as fout:
            carry = ""
            while True:
                chunk = fin.read(CHUNK)
                if not chunk:
                    break
                buf = carry + chunk
                # 从最后一个 "ip" 键处切开：它之后的记录可能不完整，留给下一轮
                ips = list(_RE_JSON_IP.finditer(buf))
                if ips and len(chunk) == CHUNK:
                    cut = ips[-1].start()
                    carry = buf[cut:]
                    buf = buf[:cut]
                else:
                    carry = ""
                for key in _iter_targets_from_text(buf):
                    if key in seen:
                        continue
                    seen.add(key)
                    fout.write(f"{key}\n")
                    count += 1
            if carry:
                for key in _iter_targets_from_text(carry):
                    if key in seen:
                        continue
                    seen.add(key)
                    fout.write(f"{key}\n")
                    count += 1
    except Exception:
        # 解析失败时保证 targets_file 存在（空文件），避免下游 Resume 死循环
        try:
            if not os.path.exists(targets_file):
                open(targets_file, "w").close()
        except Exception:
            pass
    return count


def _extract_new_targets(json_path: str, out_fp, seen: set, offset_box: list,
                         lock: threading.Lock = None):
    """增量提取 masscan JSON 中的新 IP:Port，追加到 out_fp。

    内存恒定：只从上次读到的字节偏移继续读，按行正则提取，
    绝不 f.read() 整个文件、绝不 json.loads 全量解析
    （masscan -oJ 扫描途中文件没有结尾 ']'，全量 json.loads 必然抛异常，
     旧实现因此从未真正提取到目标，还每秒把整个文件读进内存 → OOM）。

    offset_box: 单元素列表，保存已消费到的字节偏移（跨调用持久化）。
    """
    try:
        with open(json_path, "rb") as f:
            f.seek(offset_box[0])
            chunk = f.read()
            if not chunk:
                return
            # 只消费到最后一个完整换行，剩余半行留给下次
            nl = chunk.rfind(b"\n")
            if nl < 0:
                return
            offset_box[0] += nl + 1
            text = chunk[:nl].decode("utf-8", errors="replace")

        for key in _iter_targets_from_text(text):
            if lock is not None:
                with lock:
                    if key in seen:
                        continue
                    seen.add(key)
                    out_fp.write(f"{key}\n")
            else:
                if key in seen:
                    continue
                seen.add(key)
                out_fp.write(f"{key}\n")
        out_fp.flush()
    except Exception:
        pass
