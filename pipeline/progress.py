"""ASNIPtest — 网页进度状态工具（pipeline 各阶段写 progress.json）。

独立于扫描主逻辑，只负责把各阶段的进度写入一个 JSON 状态文件，
供 progress_server.py 读取并在网页上可视化。任何阶段调用失败都不影响扫描本身。
"""
import json
import os
import time
import threading

# 进度状态文件：默认放项目根的 scan_data/progress.json（与 scan_plan 同一目录）
PROGRESS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "scan_data", "progress.json")

# 阶段与总结标题映射（stage 编号 → 显示名）
STAGE_NAMES = {
    "cidr": "1/6 ASN→CIDR",
    "masscan": "2/6 masscan+verify",
    "enrich": "4/6 enrich 元数据",
    "speed": "5/6 speed 测速",
    "output": "6/6 输出报告",
    "done": "✅ 完成",
}

_lock = threading.Lock()
_log_lines = []  # 最近 N 条日志
_block_log_pct = 0  # 已写日志的 block 完成度（防重复写）


def get_block_log_pct():
    return _block_log_pct


def set_block_log_pct(pct: int):
    global _block_log_pct
    _block_log_pct = pct
LOG_MAX = 100


def _default_state():
    """构造初始 progress 状态 dict。"""
    return {
        "running": True,
        "start_time": time.time(),
        "stage": None,
        "stage_name": "等待开始",
        "stage_start": None,
        "asn": [],
        "ports": "",
        "rate": 0,  # 实际扫描速率 kpps（masscan 实时写入）
        "cidr": {"status": "pending", "count": 0},
        "masscan": {"done": 0, "total": 0, "found": 0, "status": "pending"},
        "verify": {"done": 0, "total": 0, "hits": 0, "status": "pending"},
        "enrich": {"done": 0, "total": 0, "status": "pending"},
        "speed": {"done": 0, "total": 0, "status": "pending"},
        "output": {"status": "pending"},
        "verified_ips": 0,
        "report_path": None,
        "report_url": None,
        "log": [],
    }


def _read():
    """读取当前 progress 状态；不存在则返回 None（未开始）。"""
    try:
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return _default_state()


def _write(state):
    """原子写入 progress 状态文件。"""
    try:
        os.makedirs(os.path.dirname(PROGRESS_FILE), exist_ok=True)
        tmp = PROGRESS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, PROGRESS_FILE)
    except Exception:
        pass


def log(message: str):
    """追加一条日志到状态（保留最近 LOG_MAX 条）。"""
    with _lock:
        state = _read() or _default_state()
        if not isinstance(state, dict):
            state = _default_state()
        lines = state.get("log") or []
        lines.append("[%s] %s" % (time.strftime("%H:%M:%S"), message))
        state["log"] = lines[-LOG_MAX:]
        state["running"] = True
        _write(state)


def stage(stage_key: str, asn=None, ports=None, rate=None):
    """切换阶段。stage_key ∈ STAGE_NAMES。"""
    with _lock:
        state = _read() or _default_state()
        state["stage"] = stage_key
        state["stage_name"] = STAGE_NAMES.get(stage_key, stage_key)
        state["stage_start"] = time.time()
        state["running"] = True
        if asn is not None:
            state["asn"] = asn
        if ports is not None:
            state["ports"] = ports
        # rate 字段只存实际扫描速率 kpps（由 update_rate 写入），配置 pps 不覆盖
        _write(state)


def update_rate(rate: float):
    """更新扫描实时速率（kpps，来自 masscan 输出）。"""
    with _lock:
        state = _read() or _default_state()
        state["rate"] = round(rate, 2)
        _write(state)


def update_masscan_progress(done_pct: float, found: int):
    """更新 masscan 当前 block 的实时完成度（0-100，来自 masscan 进度行）。

    让面板在 block 运行期间就能看到 S2 进度在动，而不是等整个 block 结束。
    """
    with _lock:
        state = _read() or _default_state()
        if state.get("stage") != "masscan":
            state["stage"] = "masscan"
            state["stage_name"] = STAGE_NAMES["masscan"]
            state["stage_start"] = time.time()
        m = state.get("masscan") or {"done": 0, "total": 0, "found": 0, "status": "pending"}
        # 记录当前 block 完成度（done 仍为已完成的 block 数）
        m["block_pct"] = round(max(0.0, min(100.0, done_pct)), 1)
        if found and found != "?":
            try:
                m["found"] = int(found)
            except (ValueError, TypeError):
                pass
        m["status"] = "running"
        state["masscan"] = m
        state["running"] = True
        _write(state)


def masscan(done: int, total: int, found: int = 0):
    """更新 masscan 阶段进度。"""
    with _lock:
        state = _read() or _default_state()
        if state.get("stage") != "masscan":
            state["stage"] = "masscan"
            state["stage_name"] = STAGE_NAMES["masscan"]
            state["stage_start"] = time.time()
        state["masscan"] = {
            "done": done, "total": total,
            "found": found, "status": "running",
        }
        state["running"] = True
        _write(state)


def enrich(done: int, total: int):
    """更新 enrich 阶段进度。"""
    with _lock:
        state = _read() or _default_state()
        state["enrich"] = {"done": done, "total": total, "status": "running"}
        state["running"] = True
        _write(state)


def speed(done: int, total: int, avg_mbps: float = 0.0):
    """更新 speed 阶段进度。avg_mbps 为当前平均测速速率。"""
    with _lock:
        state = _read() or _default_state()
        state["speed"] = {"done": done, "total": total, "status": "running", "avg_mbps": avg_mbps}
        state["actual_speed"] = avg_mbps
        state["running"] = True
        _write(state)


def verified(count: int):
    """记录已验证 IP 数量（masscan 完成后）。"""
    with _lock:
        state = _read() or _default_state()
        state["verified_ips"] = count
        state["running"] = True
        _write(state)


def verify_progress(done: int, total: int, hits: int = 0):
    """更新验证阶段实时进度（run_verify 每秒回调）。

    面板 S3 显示真实验证进度（不再跟 masscan 进度走）。

    注意：流式扫描下 masscan 与 verify 交替进行，这里**不切换 stage**——
    stage 由 masscan 侧维护（"masscan"），否则两者互相抢 stage，
    会导致 S2 被误判为 waiting、ETA 落到兜底分支。
    验证是否活跃改由 verify.active 标记表达。
    """
    with _lock:
        state = _read() or _default_state()
        v = state.get("verify") or {"done": 0, "total": 0, "hits": 0, "status": "pending"}
        v["done"] = done
        v["total"] = total
        v["hits"] = hits
        v["active"] = done < total          # 当前是否正在验证
        v["last_update"] = time.time()
        v["status"] = "running" if done < total else "done"
        state["verify"] = v
        # 已验证命中总数：由调用方传入累计值（跨 block 累加），直接覆盖
        state["verified_ips"] = hits
        state["running"] = True
        _write(state)


def output(status: str = "running", report_path=None, report_url=None,
           done: int = 0, total: int = 0):
    """更新 output 阶段状态。

    done/total 提供报告生成的真实完成度（如 1/3 合并数据、2/3 写 CSV、3/3 写 JSON），
    面板 S6 据此显示真实百分比，而非恒 0。
    """
    with _lock:
        state = _read() or _default_state()
        o = state.get("output") or {}
        if not isinstance(o, dict):
            o = {}
        o["status"] = status
        if total:
            o["done"] = done
            o["total"] = total
        state["output"] = o
        if report_path:
            state["report_path"] = report_path
        if report_url:
            state["report_url"] = report_url
        state["running"] = True
        _write(state)


def done(report_path=None, report_url=None):
    """标记整个扫描完成。"""
    with _lock:
        state = _read() or _default_state()
        state["running"] = False
        state["stage"] = "done"
        state["stage_name"] = STAGE_NAMES["done"]
        # 保留 done/total 分母，让面板 S6 收在 100%
        o = state.get("output") or {}
        if not isinstance(o, dict):
            o = {}
        o["status"] = "done"
        _t = o.get("total") or 0
        if _t:
            o["done"] = _t
        state["output"] = o
        if report_path:
            state["report_path"] = report_path
        if report_url:
            state["report_url"] = report_url
        state["end_time"] = time.time()
        _write(state)


def reset():
    """扫描开始前重置状态（清空上次）。"""
    with _lock:
        state = _default_state()
        state["start_time"] = time.time()
        _write(state)
