#!/usr/bin/env python3
"""ASNIPtest — 网页进度面板（独立服务，端口 8082）。

用法（扫描过程中另开一个终端或后台运行）：
    python3 progress_server.py [--port 8082] [--public-ip <公网IP>]

接受 --public-ip 参数显示公网可访问地址（而非 0.0.0.0）。

提供（**白名单路由**，其余一律 404）：
    /               — 进度面板（深色精致 UI，自动 2s 刷新）
    /progress.json  — 进度数据（供页面轮询）
    /results        — 扫描完成后的结果下载页
    /results.json   — 结果文件列表
    /joke           — 本地笑话接口
    /diag           — 自诊断
    /static/*       — 面板静态资源（背景图等）
    /output_*.csv|json — 结果文件下载（仅这一种文件名模式）

安全模型（面板监听公网，必须防护）：
  1. 访问令牌：**一次性**，由父进程（asnip.py）在 attach 进 screen 会话时
     随机生成，通过环境变量 ASNIP_PANEL_TOKEN 注入；detach 即失效。
     不落盘、不进日志、不进 ps 命令行。所有请求必须带 ?k=<token> 或
     Cookie/Header，校验失败 401。首次带 token 访问会下发 HttpOnly Cookie。
     （独立运行本脚本时可回退读同目录 access.token 文件，仅调试用。）
  2. 白名单路由：绝不回落到文件系统遍历（handler 基类是
     BaseHTTPRequestHandler，没有 translate_path），否则整个安装目录
     （install.sh / asnip.py / data/*.mmdb / .version）会变成公开
     文件服务器——实测曾可被任意下载，GeoLite2 库外泄还违反其 EULA。
  3. 只允许 GET/HEAD：其他方法 405，杜绝被当成代理或写入端点。
  4. 绝不代理转发：本服务不含任何 upstream 请求逻辑，不可能成为公共代理。
  5. 生命周期跟随 attach：detach 后父进程会 kill 本进程，端口彻底关闭。
"""
import argparse
import hmac
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---- 路径 ----
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = SCRIPT_DIR
SCAN_DIR = os.path.join(PROJECT_DIR, "scan_data")
PROGRESS_FILE = os.path.join(SCAN_DIR, "progress.json")
TOKEN_FILE = os.path.join(PROJECT_DIR, "access.token")

DEFAULT_PORT = 8082
PUBLIC_IP = None  # 可在命令行通过 --public-ip 覆盖

_last_req_ms = None  # 最近一次请求处理耗时(ms)，作为网络延迟近似

ACCESS_TOKEN = ""    # 一次性令牌：ASNIP_PANEL_TOKEN 环境变量或 access.token 文件
COOKIE_NAME = "asnip_k"
# 允许下载的结果文件名（严格限定，避免任意文件读取）
_RE_RESULT_FILE = re.compile(r"^/output_[A-Za-z0-9._-]+\.(csv|json)$")


def _load_token():
    """读取访问令牌。

    优先级：环境变量 ASNIP_PANEL_TOKEN（父进程 attach 时注入的一次性
    token）→ access.token 文件。两者都无则不启用鉴权。

    ⚠️ 绝不从命令行参数读 token —— 进程命令行对 `ps aux` 全用户可见。
    """
    global ACCESS_TOKEN
    env_tok = (os.environ.get("ASNIP_PANEL_TOKEN") or "").strip()
    if env_tok:
        ACCESS_TOKEN = env_tok
        return ACCESS_TOKEN
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            ACCESS_TOKEN = f.read().strip()
    except Exception:
        ACCESS_TOKEN = ""
    return ACCESS_TOKEN


def _installed_commit():
    """读取 .version 里的 commit（供 /diag 显示，排查版本用）。"""
    try:
        with open(os.path.join(PROJECT_DIR, ".version"), "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("commit="):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return "unknown"


def _proc_thread_count():
    """整机运行中的进程/线程数（Linux 读 /proc/loadavg 的 running 分子）。

    面板"活跃线程"以前是写死的 4/8 常量（用户零容忍写死值）。
    这里取系统真实的可运行任务数，与是否在扫描无关。
    """
    try:
        with open("/proc/loadavg") as f:
            parts = f.read().split()
        # 格式: 0.00 0.01 0.05 1/234 12345 —— 第 4 段是 running/total
        if len(parts) >= 4 and "/" in parts[3]:
            return int(parts[3].split("/")[1])
    except Exception:
        pass
    try:
        import threading
        return threading.active_count()
    except Exception:
        return 0



def _load_progress():
    try:
        with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _format_duration(seconds):
    if seconds is None:
        return "-"
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _result_files():
    """扫描完成的输出文件列表（output_*.csv / output_*.json）。"""
    files = []
    try:
        for fn in sorted(os.listdir(PROJECT_DIR)):
            if fn.startswith("output_") and (fn.endswith(".csv") or fn.endswith(".json")):
                fp = os.path.join(PROJECT_DIR, fn)
                files.append({
                    "name": fn,
                    "size": os.path.getsize(fp),
                    "mtime": time.strftime("%m-%d %H:%M", time.localtime(os.path.getmtime(fp))),
                })
    except Exception:
        pass
    files.sort(key=lambda x: x["mtime"], reverse=True)
    return files


RESULTS_HTML = """<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ASNIPtest 扫描结果</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body{font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
       background:#0b0f1a;color:#e0e8f5;padding:18px;min-height:100vh;}
  .wrap{max-width:760px;margin:0 auto;}
  h1{font-size:20px;font-weight:700;margin-bottom:4px;}
  h1 span{background:linear-gradient(90deg,#5ad8ff,#b47cff);-webkit-background-clip:text;
          -webkit-text-fill-color:transparent;}
  .sub{color:#7a8aa6;font-size:13px;margin-bottom:18px;}
  .card{background:#121826;border:1px solid rgba(255,255,255,0.06);border-radius:12px;padding:16px;}
  a.dl{display:inline-block;margin:5px 8px 5px 0;padding:8px 16px;border-radius:8px;
       background:rgba(90,216,255,0.1);color:#5ad8ff;text-decoration:none;font-size:14px;
       transition:all 0.2s;}
  a.dl:hover{background:rgba(90,216,255,0.22);}
  .empty{color:#7a8aa6;text-align:center;padding:30px;font-size:14px;}
  .hint{color:#7a8aa6;font-size:13px;margin-top:14px;}
  @media(max-width:640px){
    body{padding:12px;}
    h1{font-size:17px;}
    .card{padding:12px;}
    a.dl{padding:7px 12px;font-size:13px;}
  }
</style>
</head>
<body>
<div class="wrap">
  <h1><span>ASNIPtest</span></h1>
  <div class="sub">扫描结果下载</div>
  <div class="card" id="links"></div>
</div>
<script>
fetch('/results.json',{cache:'no-store'}).then(r=>r.json()).then(files=>{
  const box=document.getElementById('links');
  if(!files||!files.length){ box.innerHTML='<div class="empty">暂无结果文件</div>'; return; }
  files.forEach(f=>{
    const a=document.createElement('a'); a.className='dl'; a.href='/'+f.name; a.download='';
    a.textContent=f.name+' ('+fmtBytes(f.size)+')';
    box.appendChild(a);
  });
  box.insertAdjacentHTML('beforeend','<div class="hint">共 '+files.length+' 个文件</div>');
}).catch(()=>{});
function fmtBytes(n){
  if(n>=1048576) return (n/1048576).toFixed(1)+' MB';
  if(n>=1024) return (n/1024).toFixed(1)+' KB';
  return n+' B';
}
</script>
</body>
</html>
"""


TEMPLATES_DIR = os.path.join(SCRIPT_DIR, "templates")
STATIC_DIR = os.path.join(SCRIPT_DIR, "static")


def _load_template(name: str) -> str:
    """从 templates/ 读取页面；缺失则报错（前端外挂化后必须有该文件）。"""
    p = os.path.join(TEMPLATES_DIR, name)
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


_cpu_sample = {"ts": 0, "idle": 0, "total": 0}


def _sys_cpu_mem():
    """读取系统实时 CPU/内存占用（Linux /proc）。非 Linux 返回 None。

    CPU 用两次采样差值（类似网卡速率），反映实时负载而非开机平均值。
    """
    try:
        cpu = None
        mem = None
        now = time.time()
        with open("/proc/stat") as f:
            parts = f.readline().split()
        if len(parts) >= 5:
            idle = int(parts[4])
            total = sum(int(x) for x in parts[1:])
            dt = now - _cpu_sample["ts"]
            if _cpu_sample["ts"] > 0 and dt > 0:
                d_total = total - _cpu_sample["total"]
                d_idle = idle - _cpu_sample["idle"]
                if d_total > 0:
                    cpu = max(0.0, min(100.0, (1 - d_idle / d_total) * 100))
            _cpu_sample.update(ts=now, idle=idle, total=total)
            if cpu is None:
                cpu = 0.0
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                k, v = line.split(":", 1)
                meminfo[k] = int(v.strip().split()[0])
            mem_total = meminfo.get("MemTotal", 0)
            mem_avail = meminfo.get("MemAvailable", 0)
            mem = 0.0 if mem_total == 0 else (1 - mem_avail / mem_total) * 100
        return cpu, mem
    except Exception:
        return None, None


# ---- 背景图国内/国外分流 ----
BG_GITHUB = "https://raw.githubusercontent.com/take2be/ASNIPtest/master/static/bg/res_148882796.png"
BG_MIRROR = "https://cdn.jsdelivr.net/gh/take2be/ASNIPtest@master/static/bg/res_148882796.png"
_geo_cache = {}  # ip -> (country_code, timestamp)
_GEO_TTL = 3600  # 缓存1小时

# ---- 网卡实时速率（读 /proc/net/dev，两次采样差值）----
_net_sample = {"ts": None, "rx": 0, "tx": 0}
_main_iface = None  # 主网卡名（默认路由所在网卡）


def _get_main_iface():
    """通过 /proc/net/route 找默认路由对应的网卡（等价于 ip route 里的 default）。"""
    global _main_iface
    if _main_iface:
        return _main_iface
    try:
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.split()
                # 格式: Iface Destination Gateway Flags ...
                if len(parts) >= 2 and parts[1] == "00000000":  # Destination=0.0.0.0
                    _main_iface = parts[0]
                    return _main_iface
    except Exception:
        pass
    return None


def _net_rate():
    """读取主网卡实时收发速率（PPS，包/秒）。跨平台：Linux 读 /proc，Windows/macOS 用 psutil。

    等价于 `ip -s link show` 取 RX/TX 行 packets 列做两次采样差：
      TX PPS (发包速率) / RX PPS (收包速率)
    """
    global _net_sample
    try:
        rx = tx = 0
        iface = None
        try:
            # Linux: /proc/net/dev + 默认路由主网卡
            # 格式: face: rx_bytes rx_packets ... tx_bytes tx_packets ...
            iface = _get_main_iface()
            with open("/proc/net/dev") as f:
                for line in f:
                    if ":" not in line:
                        continue
                    name, rest = line.split(":", 1)
                    name = name.strip()
                    if iface and name != iface:
                        continue
                    parts = rest.split()
                    if len(parts) >= 10:
                        rx += int(parts[1])   # rx_packets
                        tx += int(parts[9])   # tx_packets
                        if not iface and name != "lo":
                            iface = name
        except (IOError, OSError):
            # 非 Linux: psutil 跨平台读（packets）
            import psutil
            counters = psutil.net_io_counters(pernic=True)
            for name, c in counters.items():
                ln = name.lower()
                if "loopback" in ln or "virtual" in ln or "vethernet" in ln or ln in ("lo",):
                    continue
                rx += c.packets_recv
                tx += c.packets_sent
        now = time.time()
        if _net_sample["ts"] is None:
            _net_sample.update(ts=now, rx=rx, tx=tx)
            return 0.0, 0.0
        dt = now - _net_sample["ts"]
        if dt <= 0:
            return 0.0, 0.0
        # 包数差 → 包/秒（pps）
        rx_pps = (rx - _net_sample["rx"]) / dt
        tx_pps = (tx - _net_sample["tx"]) / dt
        _net_sample.update(ts=now, rx=rx, tx=tx)
        return max(0.0, rx_pps), max(0.0, tx_pps)
    except Exception:
        return 0.0, 0.0


def _is_cn_ip(client_ip: str) -> bool:
    """判断访问者 IP 是否来自国内（走 ip-api.com，带缓存）。

    失败时保守返回 False（直连 GitHub），保证功能可用。
    """
    if not client_ip or client_ip in ("127.0.0.1", "::1"):
        return False
    cached = _geo_cache.get(client_ip)
    if cached and time.time() - cached[1] < _GEO_TTL:
        return cached[0] == "CN"
    try:
        import urllib.request as _ur
        url = f"http://ip-api.com/json/{client_ip}?fields=countryCode"
        with _ur.urlopen(url, timeout=5) as r:
            data = json.loads(r.read().decode("utf-8"))
        is_cn = data.get("countryCode") == "CN"
        _geo_cache[client_ip] = (data.get("countryCode"), time.time())
        return is_cn
    except Exception:
        return False


def _bg_url_for(client_ip: str) -> str:
    """按访问者来源返回背景图 URL：国内走 jsDelivr 镜像，国外直连 GitHub。"""
    return BG_MIRROR if _is_cn_ip(client_ip) else BG_GITHUB


# ---- 中文笑话池（本地接口，不依赖第三方 API，国内外 VPS 均可用）----
JOKES = [
    "今天天气真好，我的心情却像被猫抓过的毛线球。",
    "为什么手机总是没电？因为它太'放电'了。",
    "我最近在练一种功夫——'拖延症'，已经练到炉火纯青，明天再练。",
    "人生就像心电图，一帆风顺就说明你挂了。",
    "最远的距离不是天涯海角，而是我在你面前，你却低头玩手机。",
    "我问冰箱：你为什么总是这么冷？冰箱说：因为我要保持冷静。",
    "昨天梦到自己变成了一串代码，醒来发现……我还是单身。",
    "为什么鱼总是那么聪明？因为它们在课本里游来游去。",
    "如果倒霉是一种颜色，那我肯定是彩虹。",
    "我一紧张就容易脸红，所以每次考试都像苹果。",
    "为什么时钟总是走个不停？因为它不想被时间追上。",
    "第一次去健身房，教练问我目标是什么？我说：我想变成一道闪电。教练说：那你要先学会劈叉。",
    "今天路上捡到一张彩票，结果发现是昨天的。",
    "最怕空气突然安静，最怕朋友突然的关心——是不是又要借钱？",
    "我每天靠'喝热水'治百病，现在水壶都怕我了。",
    "为什么电脑总是爱生病？因为它有太多'病毒'。",
    "我决定做一个自律的人，每天早起，然后继续躺下。",
    "吃火锅的时候，我总觉得自己是个'涮'才。",
    "为什么星星不经常眨眼？因为它们戴了隐形眼镜。",
    "世界上最遥远的距离，是我和快递之间的距离——'正在派送中'。",
    "每次想早起时，被窝都对我说：再睡五分钟，就五分钟……然后天就黑了。",
    "数学老师问：1+1=？ 我回答：窗口。老师懵了，我说：因为'窗'字里有'囱'。",
    "我最大的优点就是——我很有自知之明，知道自己没优点。",
    "为什么香蕉总是弯的？因为它不想被扶直。",
    "今天又变胖了，但我告诉自己：这是'可爱到膨胀'。",
    "每次看到别人晒美食，我就打开外卖软件，假装自己也吃了。",
    "为什么猫喜欢坐在键盘上？因为想让你'喵'一下。",
    "人生最长的路，就是外卖小哥的'已取餐'到'已送达'。",
    "如果我是一本书，那一定是《等待戈多》——因为总是在等。",
    "为什么下雨天容易忧郁？因为天空在'低气压'情绪。",
    "程序员最讨厌的两件事：一是写注释，二是别人不写注释。",
    "为什么 C 程序员分不清万圣节和圣诞节？因为 Oct 31 == Dec 25。",
    "代码跑通了，但不知道为什么；代码跑不通了，也不知道为什么。",
    "产品经理说：这个需求很简单，怎么实现我不管。",
    "周一：这周一定要早睡。周二：算了，今天把事做完再说。周五：下周一定！",
    "老板：公司就是你的家。员工：那我可以随便拿东西吗？老板：那不行。员工：所以公司不是我家。",
    "为什么程序员喜欢用暗色模式？因为亮色会亮瞎他们的钛合金狗眼。",
    "QA 走进酒吧，点了 1 杯啤酒、0 杯奶茶、-1 杯咖啡和 999 杯水。",
    "程序员眼中的世界：一切皆对象，除了女朋友。",
    "Debugging 就像是在黑屋子里找一只不存在的黑猫，而且这只猫还会咬你。",
]


def _fmt_eta(sec: float) -> str:
    """把秒格式化成 ETA 文本。"""
    sec = int(max(0, sec))
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    if h >= 24:
        d, hh = divmod(h, 24)
        return f"{d}d{hh}h"
    if h:
        return f"{h}h{m}m"
    if m:
        return f"{m}m{s}s"
    return f"{s}s"


# ETA 平滑状态：记录上次给出的估算与依据，避免读数在两次进度跳变间单调飙升
_eta_state = {"key": None, "value": None, "ts": 0.0}


def _estimate_remaining(data: dict, st: str, running: bool,
                        total_progress: float, elapsed_sec: float,
                        start: float, now: float, m: dict) -> str:
    """估算剩余时间。

    旧实现 remain = elapsed * (100 - p) / p 有两个致命问题：
      1) 放大系数 (100-p)/p 在进度极低时极大（p=1.5% 时约 66），
         每过 1 秒剩余时间就涨 1 分钟，读数完全失真；
      2) masscan 阶段的加权总进度只在整块跳变时才动，两次跳变之间
         p 不变而 elapsed 在涨 → 剩余时间单调猛涨，只在跳变瞬间回落。

    新实现：
      - masscan 阶段直接用 masscan 自己每秒报告的 block_pct（细粒度），
        按"当前块实测速度"推算本块剩余 + 其余块按同速度估算；
      - 其他阶段用该阶段自身的 done/total 与阶段耗时推算；
      - 总进度 < 3% 或样本不足时显示"估算中"，不输出荒谬数字；
      - 对同一进度读数做单调平滑：进度没变时不允许 ETA 上涨。
    """
    if not running or total_progress >= 100 or st == "done":
        return "已完成"

    eta = None
    key = None
    # 各阶段在总进度里的权重（与 total_progress 计算保持一致）
    _W = {"masscan": 55.0, "enrich": 20.0, "speed": 15.0, "output": 5.0}
    stage_start = data.get("stage_start") or start
    stage_elapsed = max(0.0, now - stage_start)
    stage_frac = None      # 当前阶段自身完成比例 0..1
    stage_remain = None    # 当前阶段自身预计剩余秒数

    if st in ("masscan", "verify"):
        blocks_total = m.get("total") or 0
        blocks_done = m.get("done", 0) or 0
        block_pct = float(m.get("block_pct", 0) or 0)
        if blocks_total > 0:
            stage_frac = min(1.0, (blocks_done + block_pct / 100.0) / blocks_total)
            key = f"masscan:{blocks_done}:{block_pct:.2f}"
            # 需要足够样本：至少扫了 20 秒且阶段完成度 > 0.5%
            if stage_elapsed >= 20 and stage_frac > 0.005:
                stage_remain = max(0.0, stage_elapsed / stage_frac - stage_elapsed)
        # 最后一块扫完但验证仍在跑（流式交替的尾段）：masscan 分数已满，
        # 此时用 verify 自己的进度算 ETA，否则只能显示"估算中"
        vd0 = data.get("verify") or {}
        if isinstance(vd0, dict) and (stage_frac is None or stage_frac >= 0.999):
            v_done = vd0.get("done", 0) or 0
            v_total = vd0.get("total", 0) or 0
            if v_total > 0 and 0 < v_done < v_total and stage_elapsed >= 20:
                stage_frac = v_done / v_total
                key = f"verify:{v_done}/{v_total}"
                stage_remain = max(0.0, stage_elapsed / stage_frac - stage_elapsed)
    elif st in ("enrich", "speed", "output"):
        d = data.get(st) or {}
        if not isinstance(d, dict):
            d = {}
        s_done = d.get("done", 0) or 0
        s_total = d.get("total", 0) or 0
        if s_total > 0 and s_done > 0:
            stage_frac = min(1.0, s_done / s_total)
            key = f"{st}:{s_done}/{s_total}"
            stage_remain = (stage_elapsed / s_done) * max(0, s_total - s_done)

    # 由"当前阶段剩余"外推"整体剩余"：
    #   剩余总权重 / 当前阶段剩余权重 —— 自归一化，无需硬编码尾部系数
    if stage_remain is not None and stage_frac is not None and stage_frac < 0.999:
        _w_key = "masscan" if st in ("masscan", "verify") else st
        w_stage_left = _W.get(_w_key, 0.0) * (1.0 - stage_frac)
        w_total_left = max(0.0, 100.0 - total_progress)
        if w_stage_left > 0.5:
            eta = stage_remain * (w_total_left / w_stage_left)

    if eta is None:
        # 样本不足或阶段刚好收尾：不给失真数字。
        # 判据用"是否已进入有实测样本的阶段"，不能只看 total_progress——
        # cidr 阶段一律先加 5%，扫描刚起步时 total_progress 就已 >3%。
        if st in ("cidr", "masscan", "verify") or total_progress < 10.0:
            return "估算中..."
        # 兜底用总进度外推，此时进度已过 10%（放大系数 < 9），读数可用
        eta = elapsed_sec * (100.0 - total_progress) / total_progress
        key = f"fallback:{total_progress:.1f}"

    # 单调平滑：同一进度读数（key 不变）内不允许 ETA 上涨，
    # 避免"进度不动、剩余时间一直涨"的观感问题
    prev_key = _eta_state.get("key")
    prev_val = _eta_state.get("value")
    if key is not None and key == prev_key and prev_val is not None:
        # 进度未变：随时间递减（至少不增长）
        decayed = max(0.0, prev_val - (now - _eta_state.get("ts", now)))
        eta = min(eta, decayed) if decayed > 0 else min(eta, prev_val)
    _eta_state.update(key=key, value=eta, ts=now)
    return _fmt_eta(eta)


def _adapt_progress(data: dict) -> dict:
    """把后端 progress.json 原始字段映射成前端期望的结构。

    前端(梦幻星尘)期望:
      total_progress / verified_count / elapsed / remaining / status
      stages: [{progress, status}] × 6
      logs: [{time, message}]
      sys: {cpu, mem, net, thread, send, recv}
    """
    now = time.time()
    # 无数据（progress.json 不存在/未开始扫描）→ 明确显示"待命"而非假 running。
    # ⚠️ 硬件信息照常读真实值：CPU/内存是**整机**占用（等价任务管理器口径），
    # 与是否在扫描无关。以前这里把 cpu/mem 写死 0，用户没扫描时看到全 0
    # 会以为面板只统计脚本自身负载。
    if not data or not data.get("start_time"):
        _cpu, _mem = _sys_cpu_mem()
        _rx, _tx = _net_rate()
        return {
            "total_progress": 0.0,
            "verified_count": 0,
            "elapsed": "00:00",
            "remaining": "--",
            "status": "waiting",
            "stages": [{"progress": 0.0, "status": "waiting"} for _ in range(6)],
            "logs": [],
            "asn": [],
            "rate": 0,
            "report_url": "/results",
            "report_files": [],
            "sys": {
                "cpu": round(_cpu or 0.0, 1),
                "mem": round(_mem or 0.0, 1),
                "net": _last_req_ms if _last_req_ms else 20.0,
                "thread": _proc_thread_count(),
                "send": round(_tx or 0.0, 1),
                "recv": round(_rx or 0.0, 1),
            },
        }
    st = data.get("stage") or "waiting"
    running = data.get("running", True)
    start = data.get("start_time") or now

    # 总进度：各阶段加权（cidr 5% / masscan 55% / enrich 20% / speed 15% / output 5%）
    m = data.get("masscan") or {}
    e = data.get("enrich") or {}
    s = data.get("speed") or {}
    c = data.get("cidr") or {}
    total_progress = 0.0
    if st in ("cidr", "masscan", "verify", "enrich", "speed", "output", "done") or m.get("done"):
        total_progress += 5.0
    if m.get("total"):
        # masscan 进度 = 已完成 block + 当前 block 实时完成度
        # 注意：最后一块完成后 done 已计满而 block_pct 仍停在 100，
        # 不夹取会算出 150% → 总进度虚高（enrich 刚开始就显示 90%）
        done_blocks = m.get("done", 0) or 0
        block_pct = m.get("block_pct", 0) or 0
        masscan_frac = min(1.0, (done_blocks + block_pct / 100.0) / m["total"])
        total_progress += 55.0 * masscan_frac
    if e.get("total"):
        total_progress += 20.0 * (e.get("done", 0) / e["total"])
    if s.get("total"):
        total_progress += 15.0 * (s.get("done", 0) / s["total"])
    if st == "output" or st == "done":
        # output 阶段按真实完成度计入（合并→生成→写盘→收尾），不再一次性加满
        od = data.get("output") or {}
        if not isinstance(od, dict):
            od = {}
        if st == "done" or od.get("status") == "done":
            total_progress += 5.0
        elif od.get("total"):
            total_progress += 5.0 * min(1.0, (od.get("done", 0) or 0) / od["total"])
    if not running:
        total_progress = 100.0
    total_progress = min(100.0, max(0.0, total_progress))

    # 已用时间 / 剩余时间
    elapsed_sec = max(0, now - start)
    h, rem = divmod(int(elapsed_sec), 3600)
    mm, ss = divmod(rem, 60)
    elapsed = f"{h:02d}:{mm:02d}:{ss:02d}" if h else f"{mm:02d}:{ss:02d}"
    remain = _estimate_remaining(data, st, running, total_progress,
                                 elapsed_sec, start, now, m)

    # 阶段状态（6 条: S1 cidr / S2 masscan / S3 verify / S4 enrich / S5 speed / S6 output）
    # 流式扫描下 S2 与 S3 交替进行，两者都可能同时 active
    _vd = data.get("verify") or {}
    if not isinstance(_vd, dict):
        _vd = {}
    _verify_active = bool(_vd.get("active")) or (
        (_vd.get("total") or 0) > 0 and (_vd.get("done", 0) or 0) < (_vd.get("total") or 0)
    )
    _post_masscan = st in ("enrich", "speed", "output", "done")
    stages = []
    stage_defs = [
        ("cidr", "done" if st != "cidr" else "active"),
        ("masscan", "active" if st in ("masscan", "verify") else ("done" if _post_masscan else "waiting")),
        # S3 verify：流式交替，只要 verify 有实时数据就算 active
        ("verify", "active" if (_verify_active or st == "verify") else ("done" if _post_masscan else "waiting")),
        ("enrich", "active" if st == "enrich" else ("done" if st in ("speed", "output", "done") else "waiting")),
        ("speed", "active" if st == "speed" else ("done" if st in ("output", "done") else "waiting")),
        ("output", "active" if st == "output" else ("done" if st == "done" else "waiting")),
    ]
    for key, default_status in stage_defs:
        if key == "output":
            # S6 报告生成：用 output.done/total 反映真实完成度（合并→生成→写盘→收尾）
            od = data.get("output") or {}
            if not isinstance(od, dict):
                od = {}
            o_done = od.get("done", 0) or 0
            o_total = od.get("total", 0) or 0
            if st == "done" or od.get("status") == "done":
                prog, status = 100.0, "done"
            elif o_total:
                prog = min(100.0, o_done / o_total * 100)
                status = "active" if st == "output" else default_status
            else:
                prog = 100.0 if default_status == "done" else 0.0
                status = default_status
            stages.append({"progress": round(prog, 1), "status": status})
            continue
        if key == "verify":
            # 真实验证进度：verify 字段（done/total，run_verify 每秒回调写入，
            # 分母是"全部块的 targets 估算总量"，所以 S3 反映累计工作量）
            v_done = _vd.get("done", 0) or 0
            v_total = _vd.get("total", 0) or 0
            if v_total:
                prog = min(100.0, v_done / v_total * 100)
                if _post_masscan:
                    prog, status = 100.0, "done"
                else:
                    status = "active"
            else:
                # 无 verify 数据（尚未开始验证）
                if _post_masscan:
                    prog, status = 100.0, "done"
                elif m.get("total"):
                    prog = 0.0
                    status = "active" if st in ("masscan", "verify") else "waiting"
                else:
                    prog = 0.0
                    status = default_status
            stages.append({"progress": round(prog, 1), "status": status})
            continue
        d = data.get(key) or {}
        done = d.get("done", 0) or 0
        total = d.get("total", 0) or 0
        if key == "masscan":
            # masscan 进度 = 已完成 block + 当前 block 实时完成度（夹到 100%）
            bp = m.get("block_pct", 0) or 0
            prog = min(100.0, ((done + bp / 100.0) / total) * 100) if total else (
                100.0 if default_status == "done" else 0.0)
            status = default_status
            if _post_masscan:
                prog, status = 100.0, "done"
            elif total and (done > 0 or bp > 0):
                status = "active"
            stages.append({"progress": round(prog, 1), "status": status})
            continue
        prog = (done / total * 100) if total else (100.0 if default_status == "done" else 0.0)
        status = default_status
        if total and done >= total:
            status = "done"
        elif total and done > 0:
            status = "active"
        stages.append({"progress": round(prog, 1), "status": status})

    # 日志：后端存的是 "[HH:MM:SS] msg" 字符串，转成 {time, message}
    logs = []
    for line in (data.get("log") or [])[-50:]:
        if isinstance(line, str) and len(line) > 10 and line[0] == "[":
            logs.append({"time": line[1:9], "message": line[10:].strip()})
        else:
            logs.append({"time": time.strftime("%H:%M:%S"), "message": str(line)})

    # 系统状态：CPU/内存读 /proc（整机口径）；收发速率读网卡实时数据
    cpu, mem = _sys_cpu_mem()
    rx_pps, tx_pps = _net_rate()
    thread = _proc_thread_count()

    # 网络延迟：用最近一次轮询请求的实际处理耗时（真实往返时间，会变化）
    latency = _last_req_ms if _last_req_ms else 20.0

    return {
        "total_progress": round(total_progress, 1),
        # 已验证 IP：跨 block 累计的验证命中总数。
        # 不再回退到 masscan 的 found（那是"开放端口数"，量级完全不同，
        # 验证一开始就会从 50000 掉到 100，看起来像数据错乱）
        "verified_count": data.get("verified_ips") or 0,
        "elapsed": elapsed,
        "remaining": remain,
        "status": "done" if (st == "done" or not running and total_progress >= 100) else ("running" if running else "waiting"),
        "stages": stages,
        "logs": logs,
        "rate": data.get("rate") or 0,  # 扫描速率 kpps（masscan 实时写入）
        # 扫描的 ASN 列表（如 ["36002"]）
        "asn": data.get("asn") or [],
        # 报告下载：优先具体报告文件，否则指向结果列表页
        "report_url": data.get("report_url") or (
            data.get("report_path") if data.get("report_path") else "/results"
        ),
        "report_files": [f["name"] for f in (_result_files() or [])],
        "sys": {
            "cpu": round(cpu, 1) if cpu is not None else 0,
            "mem": round(mem, 1) if mem is not None else 0,
            "net": round(latency, 1),
            "thread": thread,
            "send": round(tx_pps, 1),  # 网卡发包速率 pps
            "recv": round(rx_pps, 1),  # 网卡收包速率 pps
        },
    }


class _ProgressHandler(BaseHTTPRequestHandler):
    """进度页 / 数据 / 结果下载处理器（纯白名单）。

    ⚠️ 基类必须是 BaseHTTPRequestHandler，不能是 SimpleHTTPRequestHandler：
    后者自带 translate_path/list_directory 等文件系统遍历能力，一旦某条
    路径漏判就会把整个安装目录暴露出去。用 Base 版从根上没有这条退路。
    """

    server_version = "ASNIPtest"
    sys_version = ""

    # 只用于给白名单命中的响应挑 Content-Type（不做任何文件系统探测）
    extensions_map = {
        ".csv": "text/csv; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".html": "text/html; charset=utf-8",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
        ".gif": "image/gif",
        ".svg": "image/svg+xml",
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".woff2": "font/woff2",
        ".ico": "image/x-icon",
    }

    def _client_token(self):
        """从 ?k= / Cookie / X-Access-Token 三处取令牌。"""
        # 1) 查询参数
        if "?" in self.path:
            q = self.path.split("?", 1)[1]
            for kv in q.split("&"):
                if kv.startswith("k="):
                    return kv[2:]
        # 2) Cookie
        try:
            raw = self.headers.get("Cookie") or ""
            for part in raw.split(";"):
                part = part.strip()
                if part.startswith(COOKIE_NAME + "="):
                    return part[len(COOKIE_NAME) + 1:]
        except Exception:
            pass
        # 3) 自定义头（供脚本/API 调用）
        try:
            return self.headers.get("X-Access-Token") or ""
        except Exception:
            return ""

    def _authorized(self):
        """校验访问令牌。未配置 token 时放行（本地调试）。"""
        if not ACCESS_TOKEN:
            return True
        got = self._client_token() or ""
        # 定长比较，避免时序侧信道
        return hmac.compare_digest(got, ACCESS_TOKEN)

    def _deny(self):
        """401：不泄漏任何项目信息，也不提示 token 长什么样。"""
        body = (b"401 Unauthorized\n\n"
                b"ASNIPtest panel requires a one-time access token.\n"
                b"Attach the screen session to get a fresh link.\n")
        self.send_response(401)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _security_headers(self):
        """统一安全响应头（防嵌套、防嗅探、不进缓存）。"""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def do_POST(self):
        self._reject_method()

    def do_PUT(self):
        self._reject_method()

    def do_DELETE(self):
        self._reject_method()

    def do_PATCH(self):
        self._reject_method()

    def do_CONNECT(self):
        # 明确拒绝 CONNECT：绝不能被当成 HTTP 代理隧道
        self._reject_method()

    def do_OPTIONS(self):
        self._reject_method()

    def _reject_method(self):
        body = b"405 Method Not Allowed\n"
        try:
            self.send_response(405)
            self.send_header("Allow", "GET, HEAD")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass

    def do_HEAD(self):
        # HEAD 与 GET 同样鉴权；只回头不回体
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def do_GET(self):
        global _last_req_ms
        _t0 = time.time()
        self._req_t0 = _t0

        # ---- 绝对路径 / 代理式请求直接拒绝（http://host/path 形式）----
        if self.path.startswith("http://") or self.path.startswith("https://"):
            self._reject_method()
            return

        route = self.path.split("?")[0]
        # 规范化，杜绝 /../ 穿越
        route = "/" + route.lstrip("/")
        if ".." in route:
            self.send_error(404)
            return

        # ---- 鉴权（白名单之前）----
        if not self._authorized():
            self._deny()
            return

        if route in ("/", "/progress", "/index.html"):
            html = _load_template("index.html")
            # 背景图国内/国外分流：按访问者来源注入 URL
            client_ip = self.client_address[0] if self.client_address else ""
            html = html.replace("{{BG_URL}}", _bg_url_for(client_ip))
            self._send_text(html, "text/html; charset=utf-8", set_cookie=True)
            return
        if route == "/results":
            self._send_text(RESULTS_HTML, "text/html; charset=utf-8", set_cookie=True)
            return
        if route == "/progress.json":
            data = _load_progress()
            # 注入公网IP和端口，供前端显示访问地址
            if PUBLIC_IP:
                data["public_ip"] = PUBLIC_IP
            data["progress_port"] = DEFAULT_PORT
            # 适配成前端(梦幻星尘)期望的结构
            adapted = _adapt_progress(data)
            adapted["public_ip"] = data.get("public_ip")
            adapted["progress_port"] = data.get("progress_port")
            self._send_json(adapted)
            return
        if route == "/results.json":
            self._send_json(_result_files())
            return
        if route == "/joke":
            import random as _rnd
            self._send_json({"joke": _rnd.choice(JOKES)})
            return
        if route == "/diag":
            # 自诊断：progress.json 存在性/修改时间 + 已装版本，定位数据链路断点。
            # 只暴露排查必需信息，不返回绝对路径（避免泄漏目录结构）。
            diag = {
                "exists": os.path.isfile(PROGRESS_FILE),
                "mtime": None,
                "size": None,
                "template_exists": os.path.isfile(os.path.join(TEMPLATES_DIR, "index.html")),
                "version": _installed_commit(),
                "auth": bool(ACCESS_TOKEN),
            }
            if diag["exists"]:
                _st = os.stat(PROGRESS_FILE)
                diag["mtime"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(_st.st_mtime))
                diag["size"] = _st.st_size
            self._send_json(diag)
            return
        # /static/* 静态资源（背景图等）
        if route.startswith("/static/"):
            rel = route[len("/static/"):]
            fp = os.path.normpath(os.path.join(STATIC_DIR, rel))
            if os.path.isfile(fp) and fp.startswith(os.path.normpath(STATIC_DIR) + os.sep):
                _, ext = os.path.splitext(fp)
                ctype = self.extensions_map.get(ext.lower(), "application/octet-stream")
                self._send_file(fp, ctype)
                return
            self.send_error(404)
            return
        # 结果文件下载：仅 /output_*.csv|json，且必须位于 PROJECT_DIR 下
        if _RE_RESULT_FILE.match(route):
            fp = os.path.normpath(os.path.join(PROJECT_DIR, route.lstrip("/")))
            if os.path.isfile(fp) and os.path.dirname(fp) == os.path.normpath(PROJECT_DIR):
                _, ext = os.path.splitext(fp)
                self.send_response(200)
                self.send_header("Content-Type", self.extensions_map.get(ext.lower(), "application/octet-stream"))
                self.send_header("Content-Disposition", f"attachment; filename={os.path.basename(fp)}")
                self.send_header("Content-Length", str(os.path.getsize(fp)))
                self._security_headers()
                self.end_headers()
                if getattr(self, "_head_only", False):
                    return
                with open(fp, "rb") as f:
                    try:
                        while True:
                            chunk = f.read(65536)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                return
            self.send_error(404)
            return
        # ---- 白名单未命中：一律 404 ----
        # 基类是 BaseHTTPRequestHandler，没有文件系统回落路径：
        # 安装目录（install.sh / asnip.py / pipeline/*.py / data/*.mmdb /
        # access.token / .version）永远不可能被这里返回。
        self.send_error(404)
        return

    def _send_text(self, html, ctype, set_cookie=False):
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self._security_headers()
        # 首次带 ?k= 访问页面时下发 HttpOnly Cookie，之后刷新/轮询无需再带参数
        if set_cookie and ACCESS_TOKEN:
            self.send_header(
                "Set-Cookie",
                f"{COOKIE_NAME}={ACCESS_TOKEN}; Path=/; Max-Age=604800; HttpOnly; SameSite=Strict",
            )
        self.end_headers()
        if getattr(self, "_head_only", False):
            return
        self.wfile.write(data)

    def _send_file(self, path, ctype):
        """发送静态文件（图片等二进制资源）。"""
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(os.path.getsize(path)))
        self._security_headers()
        self.end_headers()
        if getattr(self, "_head_only", False):
            return
        with open(path, "rb") as f:
            try:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _send_json(self, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self._security_headers()
        self.end_headers()
        if getattr(self, "_head_only", False):
            return
        self.wfile.write(data)

    def log_message(self, format, *args):
        # 记录请求处理耗时（作为网络延迟近似，供面板显示）
        global _last_req_ms
        try:
            _last_req_ms = round((time.time() - self._req_t0) * 1000, 1) if hasattr(self, "_req_t0") else None
        except Exception:
            pass


args = None  # 占位, main 里赋值


def main():
    global PUBLIC_IP, PROGRESS_PORT, args, ACCESS_TOKEN
    parser = argparse.ArgumentParser(description="ASNIPtest 网页进度面板")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"监听端口（默认 {DEFAULT_PORT}）")
    parser.add_argument("--public-ip", type=str, default=None,
                        help="公网 IP 地址（自动检测，也可指定）")
    parser.add_argument("--quiet-token", action="store_true",
                        help="不在 stdout 打印 token（由父进程负责展示）")
    args = parser.parse_args()
    PUBLIC_IP = args.public_ip
    PROGRESS_PORT = args.port
    # 自动检测公网 IP（如果没指定）
    if not PUBLIC_IP:
        try:
            import urllib.request
            resp = urllib.request.urlopen("https://api.ipify.org", timeout=5)
            PUBLIC_IP = resp.read().decode().strip()
        except Exception:
            pass

    import subprocess as _sp
    try:
        try:
            _sp.run(["fuser", "-k", f"{args.port}/tcp"], capture_output=True, timeout=5)
        except FileNotFoundError:
            import socket as _sock
            _s = _sock.socket(); _s.settimeout(0.5)
            _res = _s.connect_ex(("127.0.0.1", args.port)); _s.close()
            if _res == 0:
                print(f"  ⚠ 端口 {args.port} 已被占用（无 fuser 无法释放），仍尝试启动...")
        time.sleep(0.5)
    except Exception:
        pass

    try:
        import socket as _sock
        _test = _sock.socket(); _test.settimeout(0.5)
        _res = _test.connect_ex(("127.0.0.1", args.port)); _test.close()
        if _res == 0:
            print(f"  ✗ 端口 {args.port} 仍被占用，无法启动进度面板")
            return

        server = HTTPServer(("0.0.0.0", PROGRESS_PORT), _ProgressHandler)

        # 访问令牌：优先环境变量（父进程 attach 时注入的一次性 token），
        # 回退 access.token 文件。**绝不从命令行参数取** —— ps aux 全用户可见。
        _load_token()

        display_ip = PUBLIC_IP or "0.0.0.0"
        if ACCESS_TOKEN:
            if args.quiet_token:
                # token 由父进程打印到已 attach 的终端；这里 stdout 会进
                # scan_data/progress.log（文件权限不可控），绝不落盘 token
                print(f"  📡 进度面板已启动: {display_ip}:{args.port}（需 token 访问）")
            else:
                print(f"  📡 ASNIPtest 进度面板: http://{display_ip}:{args.port}/?k={ACCESS_TOKEN}")
                print("     ↑ 必须带 ?k=<token>，首次访问后写入 Cookie，之后刷新无需再带")
        else:
            print(f"  📡 ASNIPtest 进度面板: http://{display_ip}:{args.port}/")
            print("  ⚠ 无访问令牌，面板处于无鉴权状态")
        print("  按 Ctrl+C 停止")
        server.serve_forever()
    except OSError as e:
        print(f"  ✗ 启动失败: {e}")
    except KeyboardInterrupt:
        print("\n  服务已停止")
        try:
            server.server_close()
        except Exception:
            pass


if __name__ == "__main__":
    main()