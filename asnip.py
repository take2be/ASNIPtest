#!/usr/bin/env python3
"""ASNIPtest CLI — 一键 ASN 反代 IP 优选工具。

用法:
  asnip scan              # 交互模式
  asnip scan 13335,209554 # 直接指定 ASN
"""
import argparse
import hmac
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class _DownloadHandler(BaseHTTPRequestHandler):
    """结果文件下载处理器（**白名单**，只放行结果文件）。

    安全要点（曾经的漏洞，别改回去）：
      - 原实现继承 SimpleHTTPRequestHandler 且不限制路由，等于把整个
        ~/.asnip/src/ 变成公开文件服务器：install.sh / asnip.py /
        pipeline/*.py / data/*.mmdb / access.token 全可被任意下载
        （mmdb 外泄还违反 GeoLite2 EULA）。现在改为纯白名单。
      - 只允许 GET/HEAD；其余方法及绝对 URL 请求一律 405，杜绝被当代理。
      - 必须带一次性 token（?k= / Cookie / X-Access-Token）。
    """

    server_version = "ASNIPtest"
    sys_version = ""

    _CTYPE = {".csv": "text/csv; charset=utf-8", ".json": "application/json; charset=utf-8"}
    # 仅这两种文件名模式可下载
    _RE_OUTPUT = re.compile(r"^/output_[A-Za-z0-9._-]+\.(csv|json)$")
    _RE_REPORT = re.compile(r"^/report\.(csv|json)$")

    token = ""          # 由 server 实例注入（类属性兜底）
    COOKIE = "asnip_dl"

    # ---- 鉴权 ----
    def _want_token(self):
        return getattr(self.server, "access_token", "") or self.__class__.token

    def _client_token(self):
        p = getattr(self, "path", "") or ""
        if "?" in p:
            for kv in p.split("?", 1)[1].split("&"):
                if kv.startswith("k="):
                    return kv[2:]
        try:
            for part in (self.headers.get("Cookie") or "").split(";"):
                part = part.strip()
                if part.startswith(self.COOKIE + "="):
                    return part[len(self.COOKIE) + 1:]
            return self.headers.get("X-Access-Token") or ""
        except Exception:
            return ""

    def _authorized(self):
        want = self._want_token()
        if not want:
            return True
        return hmac.compare_digest(self._client_token() or "", want)

    # ---- 响应助手 ----
    def _headers_common(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def _text(self, code, body, ctype="text/plain; charset=utf-8", cookie=False):
        if isinstance(body, str):
            body = body.encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self._headers_common()
            tok = self._want_token()
            if cookie and tok:
                self.send_header(
                    "Set-Cookie",
                    f"{self.COOKIE}={tok}; Path=/; Max-Age=86400; HttpOnly; SameSite=Strict",
                )
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except Exception:
            pass

    def _reject_method(self):
        try:
            self.send_response(405)
            self.send_header("Allow", "GET, HEAD")
            self.send_header("Content-Length", "0")
            self._headers_common()
            self.end_headers()
        except Exception:
            pass

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_CONNECT = _reject_method

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        raw = getattr(self, "path", "") or "/"
        # 代理式绝对 URL：绝不转发
        if raw.startswith("http://") or raw.startswith("https://"):
            self._reject_method()
            return
        route = "/" + raw.split("?")[0].lstrip("/")
        if ".." in route:
            self._text(404, "404\n")
            return
        if not self._authorized():
            self._text(401, "401 Unauthorized\n\n"
                            "Attach the screen session to get a fresh link.\n")
            return

        if route in ("/", "/index.html"):
            self._text(200, _download_index_html(self._want_token()),
                       "text/html; charset=utf-8", cookie=True)
            return

        if self._RE_OUTPUT.match(route) or self._RE_REPORT.match(route):
            fp = os.path.normpath(os.path.join(PROJECT_DIR, route.lstrip("/")))
            if os.path.isfile(fp) and os.path.dirname(fp) == os.path.normpath(PROJECT_DIR):
                _, ext = os.path.splitext(fp)
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", self._CTYPE.get(ext.lower(),
                                                                     "application/octet-stream"))
                    self.send_header("Content-Disposition",
                                     f"attachment; filename={os.path.basename(fp)}")
                    self.send_header("Content-Length", str(os.path.getsize(fp)))
                    self._headers_common()
                    self.end_headers()
                    if self.command == "HEAD":
                        return
                    with open(fp, "rb") as f:
                        while True:
                            chunk = f.read(65536)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception:
                    pass
                return
            self._text(404, "404\n")
            return

        # 白名单未命中 → 404（绝不回落到文件系统遍历）
        self._text(404, "404\n")

    def log_message(self, format, *args):
        pass  # 安静运行，不刷日志


def _download_index_html(token: str) -> str:
    """结果下载索引页（链接自带 token，点击即可下载）。"""
    rows = []
    try:
        for fn in sorted(os.listdir(PROJECT_DIR), reverse=True):
            if not (fn.startswith("output_") or fn in ("report.csv", "report.json")):
                continue
            if not (fn.endswith(".csv") or fn.endswith(".json")):
                continue
            fp = os.path.join(PROJECT_DIR, fn)
            if not os.path.isfile(fp):
                continue
            kb = os.path.getsize(fp) / 1024.0
            mt = time.strftime("%m-%d %H:%M", time.localtime(os.path.getmtime(fp)))
            q = f"?k={token}" if token else ""
            rows.append(
                f'<tr><td><a href="/{fn}{q}" download>{fn}</a></td>'
                f"<td>{kb:.1f} KB</td><td>{mt}</td></tr>"
            )
    except Exception:
        pass
    body = "".join(rows) or '<tr><td colspan="3">暂无结果文件</td></tr>'
    return (
        "<!DOCTYPE html><html lang=zh><head><meta charset=utf-8>"
        "<meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>ASNIPtest 结果下载</title><style>"
        "body{background:#0f1220;color:#e8ecff;font-family:system-ui,-apple-system,"
        "'Segoe UI',Roboto,sans-serif;margin:0;padding:24px}"
        "h1{font-size:20px;margin:0 0 16px}"
        "table{width:100%;max-width:760px;border-collapse:collapse}"
        "td{padding:10px 8px;border-bottom:1px solid #262a44;font-size:15px}"
        "a{color:#6ea8ff;text-decoration:none}a:hover{text-decoration:underline}"
        "p{color:#8b93b8;font-size:13px;max-width:760px}"
        "</style></head><body><h1>ASNIPtest 结果下载</h1><table>"
        + body +
        "</table><p>此链接仅在 screen 会话处于 attach 状态时有效；"
        "detach 后端口立即关闭，重新 attach 会生成新链接。</p></body></html>"
    )

# ============================================================
#  配置
# ============================================================
DEFAULT_PORTS = "443,8443,2053,2083,2087,2096"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = SCRIPT_DIR


def main():
    parser = argparse.ArgumentParser(
        prog="asnip",
        description="ASNIPtest — 按 ASN 扫描第三方 Cloudflare 反代 IP",
    )
    
    subparsers = parser.add_subparsers(dest="action", help="操作类型")
    
    # 共享参数定义函数
    def add_common_args(subparser):
        subparser.add_argument("asn", nargs="*", default=[""],
                              help="ASN 号（多个用逗号分隔）")
        subparser.add_argument("--ports", default="",
                              help="端口集（默认交互输入）")
        subparser.add_argument("--port", type=int, default=8081,
                                      help="HTTP 服务端口（默认 8081）")
        subparser.add_argument("--progress-port", type=int, default=8082,
                                      help="网页进度面板端口（默认 8082）")
        subparser.add_argument("--force", action="store_true",
                              help="忽略缓存强制刷新")
        subparser.add_argument("--top", type=int, default=None,
                              help="只输出前 N 个结果")
        subparser.add_argument("--json", action="store_true",
                              help="额外输出 JSON 格式报告")
        subparser.add_argument("--no-deps", action="store_true",
                              help="跳过依赖检查")
        subparser.add_argument("--daemon", action="store_true",
                              help="断线自动续跑模式：直到 report.csv 生成才退出")
        subparser.add_argument("--rate", type=int, default=None,
                              help="masscan 扫描速率 pkts/s（不指定则交互输入，默认 2000）")
    
    # scan 子命令
    scan_parser = subparsers.add_parser("scan", help="扫描 ASN")
    add_common_args(scan_parser)
    
    # ips 子命令
    ips_parser = subparsers.add_parser("ips", help="扫描 ASN (ips 别名)")
    add_common_args(ips_parser)

    # serve 子命令：临时拉起结果下载服务（attach 门控）
    serve_parser = subparsers.add_parser("serve", help="临时拉起结果下载服务（需 attach）")
    serve_parser.add_argument("--port", type=int, default=8081,
                              help="HTTP 端口 (默认 8081)")
    serve_parser.add_argument("--progress-port", type=int, default=8082,
                              help="进度面板端口 (默认 8082)")

    # progress 子命令：拉起进度面板（对应 README 的 irds-progress）
    progress_parser = subparsers.add_parser("progress", help="进度面板 (8082)")
    progress_parser.add_argument("--port", type=int, default=8082,
                                 help="进度面板端口 (默认 8082)")
    progress_parser.add_argument("--public-ip", type=str, default=None,
                                 help="公网 IP 地址（自动获取）")

    args = parser.parse_args()

    os.chdir(PROJECT_DIR)

    # 保留 rate 标记（serve 子命令没有 rate 参数，用 getattr 安全访问）
    args.rate = getattr(args, "rate", None)

    if args.action in ("scan", "ips"):
        cmd_scan(args)
    elif args.action == "serve":
        cmd_serve(args)
    elif args.action == "progress":
        cmd_progress(args)
    else:
        parser.print_help()


def cmd_scan(args):
    """执行扫描管线。"""
    print()
    print("=" * 56)
    print("  🔍 ASNIPtest — 第三方 Cloudflare 反代 IP 优选工具")
    print("=" * 56)
    print()
    print("  快捷操作：Ctrl+Z 暂停 | fg 恢复 | Ctrl+C 停止")
    print()

    # ---- 依赖检查 ----
    if not args.no_deps:
        check_deps()

    # ---- 系统信息 ----
    _print_system_info()
    print()

    # ---- ASN/CIDR 输入（单一类型：要么全 ASN，要么全 IP 段）----
    import ipaddress as _ipaddr
    asns = []
    cidrs = []
    if args.asn and args.asn[0]:
        raw = " ".join(args.asn)
    else:
        raw = input("  输入 ASN 或 IP 段（多个用逗号分隔，如: 13335,209554 或 45.221.113.0/24）: ").strip()
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            # IP 段
            try:
                _ipaddr.IPv4Network(token, strict=False)
                cidrs.append(token.replace(" ", ""))
            except ValueError:
                print(f"  ✗ 无效 IP 段: {token}")
                return
        else:
            # ASN
            if token.upper().startswith("AS"):
                token = token[2:]
            try:
                asns.append(int(token))
            except ValueError:
                print(f"  ✗ 无效 ASN: {token}")
                return
    if asns and cidrs:
        print("  ✗ 不支持 ASN 和 IP 段混合输入，请统一用一种")
        return
    if not asns and not cidrs:
        print("  ✗ 未输入有效 ASN 或 IP 段")
        return
    if asns:
        print(f"  → ASN: {', '.join('AS' + str(a) for a in asns)}")
    else:
        print(f"  → IP 段: {', '.join(cidrs)}")
    print()

    # ---- 端口输入 ----
    ports = args.ports
    if not ports:
        if args.daemon or not sys.stdin.isatty():
            ports = DEFAULT_PORTS
        else:
            ports = input(f"  输入端口（默认 {DEFAULT_PORTS}）: ").strip() or DEFAULT_PORTS
    print(f"  → 端口: {ports}")
    print()

    # ---- 代理（仅 VPS 无交互；daemon 模式必跳过）----
    is_wsl = _is_wsl()
    proxies = None
    verify_proxy = None

    if is_wsl and not args.daemon:
        print("  🌐 检测到 WSL 环境")
        use = input("  是否需要走代理？（y/N）: ").strip().lower()
        if use in ("y", "yes"):
            addr = input("  代理地址（回车默认 127.0.0.1:10808）: ").strip()
            if not addr:
                addr = "127.0.0.1:10808"
            proxies = {"http": f"http://{addr}", "https": f"http://{addr}"}
            verify_proxy = addr
            print(f"  ✅ 代理: {addr}")
    else:
        print("  🖥  Linux 环境，默认直连")
    print()

    # ---- 测速询问：延迟与下载速度分别交互 ----
    # 非法输入不静默默认，重问；回车才走默认值
    def _ask_yn(prompt: str, default: bool) -> bool:
        if args.daemon or not sys.stdin.isatty():
            return default
        hint = "Y/n" if default else "y/N"
        while True:
            ans = input(f"  {prompt} ({hint}): ").strip().lower()
            if not ans:
                return default
            if ans in ("y", "yes"):
                return True
            if ans in ("n", "no"):
                return False
            print("    请输入 y 或 n（回车用默认值）")

    do_latency = True
    do_speed = False
    if not args.top and not args.json and not args.daemon:
        do_latency = _ask_yn("是否测延迟？", True)
        do_speed = _ask_yn("是否测下载速度？", False)
        if not do_latency and not do_speed:
            print("  → 跳过测速阶段（延迟与速度均不测）")
        elif do_speed and not do_latency:
            # 下载速度依赖握手连接，测速必然产生延迟数据，一并保留
            do_latency = True
            print("  → 测延迟 + 测下载速度")
        else:
            print(f"  → {'测延迟 + 测下载速度' if do_speed else '仅测延迟'}")
    # speed_top 语义：None=只测延迟, 0=全测(延迟+速度), -1=完全跳过
    if not do_latency and not do_speed:
        speed_top = -1
    elif do_speed:
        speed_top = 0
    else:
        speed_top = None

    # ---- 扫描速率交互 ----
    # 规则：命令行显式 --rate 则用之；否则 daemon/非交互用默认 2000；否则询问用户
    if args.rate is not None and args.rate > 0:
        scan_rate = args.rate
        print(f"  → 扫描速率: {scan_rate} pps")
    elif args.daemon or not sys.stdin.isatty():
        scan_rate = 2000
    else:
        rate_input = input("  扫描速率 pps（默认 2000）: ").strip()
        if rate_input.isdigit() and int(rate_input) > 0:
            scan_rate = int(rate_input)
        else:
            scan_rate = 2000
        print(f"  → 扫描速率: {scan_rate} pps")
    print()

    # ---- 运行管线（直接开始，无确认）----
    from pipeline.orchestrator import Orchestrator

    app = Orchestrator()
    app.proxies = proxies
    app.verify_proxy = verify_proxy

    # 主标识：ASN 或 CIDR（CIDR 的 / 换 _，用于文件名/daemon 检测）
    target_label = str(asns[0]) if asns else cidrs[0].replace("/", "_")

    # 自动清理旧扫描缓存，确保每次都是全新扫描
    scan_dir = os.path.join(app.workdir, "scan_data")
    if os.path.isdir(scan_dir):
        import shutil as _shutil
        _shutil.rmtree(scan_dir, ignore_errors=True)
        print(f"  🧹 已清理旧缓存")
        print()

    if args.daemon:
        # 后台循环：直到 report.csv 生成才退出
        import atexit
        @atexit.register
        def _on_exit():
            print("\n  守护进程退出")
        # daemon 模式：扫描期间也走 attach 门控（detach 即关端口）
        from attach_guard import AttachGuard, is_attached

        daemon_panel = _AttachPanelProc(args.progress_port)

        def _daemon_announce():
            _print_access_urls(args.progress_port, daemon_panel.token,
                               0, "", scan_done=False)

        daemon_guard = AttachGuard([daemon_panel], on_all_open=_daemon_announce)
        daemon_guard.start()
        if is_attached():
            daemon_guard.force_open()
        try:
            while True:
                app.run(
                    asns=asns,
                    cidrs=cidrs,
                    ports=ports,
                    force=False,
                    top_n=args.top,
                    speed_top=0 if args.top or args.json else 0,
                    json_output=args.json,
                    rate=scan_rate,
                )
                # 检测实际生成的结果文件 output_{主标识}_{时间戳}.csv
                newest = None
                for fn in os.listdir(PROJECT_DIR):
                    if fn.startswith(f"output_{target_label}_") and fn.endswith(".csv"):
                        fp = os.path.join(PROJECT_DIR, fn)
                        if newest is None or os.path.getmtime(fp) > os.path.getmtime(newest):
                            newest = fp
                if newest and os.path.getsize(newest) > 100:
                    print(f"\n  ✅ {os.path.basename(newest)} 已生成，守护进程退出")
                    break
                print("\n  报告未生成，10 秒后自动续跑...")
                time.sleep(10)
        finally:
            daemon_guard.stop()
        # 扫描完成 → 整理结果，进入 attach 门控的 HTTP 服务
        _prepare_results()
        _serve_attached(args.progress_port, args.port,
                        scan_done=True, progress_proc=None)
        return

    # 扫描期间的进度面板不再无条件常驻：改由 attach 门控管理。
    # 面板与扫描无法同进程（app.run 阻塞），所以仍用子进程，
    # 但只在 attach 时启动；detach 时杀掉，重新 attach 再拉起。
    from attach_guard import AttachGuard, is_attached

    panel_proc = _AttachPanelProc(args.progress_port)

    def _announce():
        _print_access_urls(args.progress_port, panel_proc.token, 0, "", scan_done=False)

    scan_guard = AttachGuard([panel_proc], on_all_open=_announce)
    scan_guard.start()
    if is_attached():
        scan_guard.force_open()

    try:
        app.run(
            asns=asns,
            cidrs=cidrs,
            ports=ports,
            force=args.force,
            top_n=args.top,
            speed_top=speed_top,
            json_output=args.json,
            rate=scan_rate,
        )
    finally:
        scan_guard.stop()

    # 扫描完成 → 整理结果，交给 attach 门控的 HTTP 服务（面板 + 下载并存）。
    # 面板必须活到前端至少完成一次 done 轮询（2s），否则页面停在 S6=0%
    # 的旧快照；_serve_attached 持续开放到 Ctrl+C，满足这一点。
    _prepare_results()
    _serve_attached(args.progress_port, args.port,
                    scan_done=True, progress_proc=None)


def cmd_serve(args):
    """serve 子命令：临时拉起结果下载 + 面板（同样受 attach 门控）。"""
    _prepare_results()
    _serve_attached(getattr(args, "progress_port", 8082), args.port,
                    scan_done=True, progress_proc=None)


def cmd_progress(args):
    """progress 子命令：前台拉起进度面板，带一次性访问令牌。

    面板监听公网，必须带令牌。令牌通过环境变量注入子进程（**不进命令行**，
    ps aux 全用户可见），进程退出即失效。
    """
    import subprocess as _sp
    import os as _os
    from attach_guard import new_token

    # 自动获取公网 IP（如果没显式指定）
    public_ip = args.public_ip
    if not public_ip:
        try:
            public_ip = _get_public_ip()
        except Exception:
            pass

    script = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "progress_server.py")
    if not _os.path.exists(script):
        print("  ✗ progress_server.py 未找到")
        return

    tok = new_token()
    print()
    print("  进度面板（前台运行，Ctrl+C 结束即关闭端口）:")
    host = public_ip or "<服务器IP>"
    print(f"    {_link(f'http://{host}:{args.port}/?k={tok}')}")
    print()
    print("  令牌一次性有效，本进程退出后链接立即失效。")
    print()

    cmd = [sys.executable, script, "--port", str(args.port), "--quiet-token"]
    if public_ip:
        cmd += ["--public-ip", public_ip]

    env = dict(os.environ)
    env["ASNIP_PANEL_TOKEN"] = tok
    try:
        _sp.run(cmd, cwd=_os.path.dirname(script), env=env)
    except KeyboardInterrupt:
        print("\n  服务已停止")


def _print_system_info():
    """打印硬件、IP、地区等系统信息。"""
    cpu = os.cpu_count() or 1
    mem = 512
    try:
        import psutil
        cpu = psutil.cpu_count(logical=False) or cpu
        mem = psutil.virtual_memory().total // (1024 * 1024)
        print(f"  硬件: {cpu}核 {mem}MB")
    except ImportError:
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        mem = int(line.split()[1]) // 1024
                        break
        except Exception:
            pass
        print(f"  硬件: {cpu}核 {mem}MB")
    except Exception:
        print(f"  硬件: {cpu}核")

    ip = "-"
    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as r:
            ip = json.loads(r.read()).get("ip", "-")
    except Exception:
        pass

    country = region = org = "-"
    if ip != "-":
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,org,as"
            with urllib.request.urlopen(url, timeout=5) as r:
                data = json.loads(r.read())
                if data.get("status") == "success":
                    country = data.get("country", "-")
                    region = data.get("regionName", "-")
                    org = data.get("org", "-")
        except Exception:
            pass

    print(f"  本机公网 IP: {ip}")
    print(f"  地区: {region}, {country}  机构: {org}")
    # 估算资源
    if cpu >= 2 and mem >= 400:
        print(f"  硬件: {cpu}核 {mem}MB → masscan 2000cps cf-scanner 200c API 32c")


def _is_wsl() -> bool:
    """检测是否在 WSL 中。"""
    try:
        return "microsoft" in platform.uname().release.lower()
    except Exception:
        return False


def _get_public_ip() -> str | None:
    """获取公网出口 IP，多 API 多重兜底。"""
    apis = [
        "https://api.ipify.org",
        "https://api-ipv4.ip.sb/ip",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    import urllib.request
    for url in apis:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                parts = ip.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return ip
        except Exception:
            continue
    return None


def _get_lan_ip() -> str | None:
    """获取本机局域网 IP。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    return None


def _start_progress_server(port: int = 8082, token: str = ""):
    """后台启动 progress_server.py，返回子进程对象；失败返回 None。

    独立子进程：即使它崩了也不影响扫描主流程。

    ⚠️ token 通过环境变量传递，**绝不放进命令行参数** —— 命令行对
    `ps aux` 全用户可见。同理面板 stdout 不再打印 token（会进日志文件）。
    """
    import subprocess as _sp
    import time as _time
    script = os.path.join(SCRIPT_DIR, "progress_server.py")
    if not os.path.exists(script):
        return None
    try:
        # 记录进度服务器日志到 scan_data/progress.log, 便于排查启动失败
        scan_dir = os.path.join(PROJECT_DIR, "scan_data")
        os.makedirs(scan_dir, exist_ok=True)
        log_file = os.path.join(scan_dir, "progress.log")
        err_log = open(log_file, "w", encoding="utf-8")
        env = dict(os.environ)
        if token:
            env["ASNIP_PANEL_TOKEN"] = token
        proc = _sp.Popen(
            [sys.executable, script, "--port", str(port), "--quiet-token"],
            stdout=err_log,
            stderr=err_log,
            cwd=PROJECT_DIR,
            env=env,
        )
        # 给一点启动时间, 然后检查子进程是否存活
        _time.sleep(1.2)
        if proc.poll() is not None:
            # 子进程已退出, 输出日志到终端
            err_log.close()
            print("  ✗ 进度面板启动失败, 日志:")
            try:
                for line in open(log_file, encoding="utf-8"):
                    print("    " + line.rstrip())
            except Exception:
                pass
            return None
        err_log.close()
        return proc
    except Exception:
        return None


def _stop_progress_server(proc):
    """停止 progress_server 子进程（尽力而为）。"""
    if proc is None:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    except Exception:
        pass


def _prepare_results() -> tuple:
    """整理结果文件（清理旧文件、生成 report.csv 稳定别名）。

    返回 (output_csv, output_json)。不启动任何服务。
    """
    results_dir = PROJECT_DIR
    output_csv = None
    output_json = None
    try:
        import glob
        cwd = os.getcwd()
        os.chdir(results_dir)
        try:
            all_csv = sorted(glob.glob("output_*.csv"), key=os.path.getmtime, reverse=True)
            if all_csv:
                output_csv = os.path.basename(all_csv[0])
            for fp in all_csv[2:]:      # 只保留最近 2 个
                try:
                    os.remove(fp)
                except Exception:
                    pass
            all_json = sorted(glob.glob("output_*.json"), key=os.path.getmtime, reverse=True)
            if all_json:
                output_json = os.path.basename(all_json[0])
            for fp in all_json[2:]:
                try:
                    os.remove(fp)
                except Exception:
                    pass
            # 复制一份为 report.csv 保持稳定 URL
            if output_csv and output_csv != "report.csv":
                try:
                    shutil.copy2(output_csv, "report.csv", follow_symlinks=False)
                except Exception:
                    pass
        finally:
            os.chdir(cwd)
    except Exception:
        pass
    return (output_csv or "report.csv", output_json or "report.json")


def _make_download_server(port: int, token: str):
    """创建（已绑定端口、未 serve）的结果下载服务。"""
    srv = HTTPServer(("0.0.0.0", port), _DownloadHandler)
    srv.access_token = token
    return srv


def _free_port(port: int):
    """释放端口上的残留进程（尽力而为）。"""
    try:
        subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, timeout=5)
        time.sleep(0.3)
    except Exception:
        pass


# 公网/内网 IP 只解析一次，缓存复用（attach/detach 可能反复触发打印）
_IP_CACHE = {}


def _cached_ips() -> tuple:
    if "lan" not in _IP_CACHE:
        try:
            _IP_CACHE["lan"] = _get_lan_ip()
        except Exception:
            _IP_CACHE["lan"] = None
    if "pub" not in _IP_CACHE:
        try:
            _IP_CACHE["pub"] = _get_public_ip()
        except Exception:
            _IP_CACHE["pub"] = None
    return _IP_CACHE.get("lan"), _IP_CACHE.get("pub")


def _print_access_urls(panel_port: int, panel_token: str,
                       dl_port: int, dl_token: str, scan_done: bool):
    """打印本次 attach 期间可用的面板/下载地址（含一次性 token）。

    只输出到已 attach 的终端，绝不写日志文件、不进进程命令行。
    """
    lan, pub = _cached_ips()
    print()
    print("=" * 58)
    print("  🔓 HTTP 服务已开放（仅本次 attach 期间有效）")
    print("=" * 58)
    if panel_token:
        print()
        print("  进度面板:")
        for ip, tag in ((pub, "公网"), (lan, "内网")):
            if ip:
                u = f"http://{ip}:{panel_port}/?k={panel_token}"
                print(f"    {tag}  {_link(u)}")
        if not lan and not pub:
            print(f"    http://localhost:{panel_port}/?k={panel_token}")
    if dl_token:
        print()
        print("  结果下载:" + ("" if scan_done else "（扫描进行中，扫完才有文件）"))
        for ip, tag in ((pub, "公网"), (lan, "内网")):
            if ip:
                u = f"http://{ip}:{dl_port}/?k={dl_token}"
                print(f"    {tag}  {_link(u)}")
        if not lan and not pub:
            print(f"    http://localhost:{dl_port}/?k={dl_token}")
    print()
    print("  detach（Ctrl+A D）后端口立即关闭，重新 attach 会生成新链接。")
    print("  彻底结束: Ctrl+C 或 Ctrl+A K Y")
    print()
    # 主动 flush：stdout 若被重定向到文件（daemon / 日志）会块缓冲，
    # 不 flush 时链接可能迟迟不出现，用户以为服务没起来
    try:
        sys.stdout.flush()
    except Exception:
        pass


class _AttachPanelProc:
    """把 progress_server 子进程包装成 AttachGatedServer 的同构接口。

    扫描期间 app.run() 阻塞主线程，面板必须独立子进程；但生命周期同样
    跟随 attach 状态 —— detach 即 kill（端口彻底关闭），重新 attach 再拉起
    并生成新 token。
    """

    def __init__(self, port: int):
        self.name = "进度面板"
        self.port = port
        self._proc = None
        self._token = ""

    @property
    def is_open(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def token(self) -> str:
        return self._token

    def open(self) -> bool:
        if self.is_open:
            return True
        from attach_guard import new_token
        self._token = new_token()
        _free_port(self.port)
        self._proc = _start_progress_server(port=self.port, token=self._token)
        if self._proc is None:
            self._token = ""
            return False
        return True

    def close(self, quiet: bool = False):
        p, self._proc = self._proc, None
        self._token = ""
        _stop_progress_server(p)


def _serve_attached(panel_port: int, dl_port: int, scan_done: bool = True,
                    progress_proc=None):
    """attach 驱动的 HTTP 服务：attach 时开放，detach 时关闭，直到 Ctrl+C。

    面板与下载服务都由本函数托管。progress_proc 是扫描期间已在跑的面板
    子进程（若有），这里先停掉它，之后统一交给 attach 门控管理。
    """
    from attach_guard import AttachGatedServer, AttachGuard, is_attached

    # 扫描期间的常驻面板交回门控管理（避免两份面板抢 8082）
    if progress_proc is not None:
        _stop_progress_server(progress_proc)
        time.sleep(0.3)

    _free_port(panel_port)
    _free_port(dl_port)

    # 面板同样用子进程（progress_server 在本进程内 import 会与扫描模块
    # 共享全局状态，且端口重绑麻烦），统一走 _AttachPanelProc
    panel = _AttachPanelProc(panel_port)
    dl = AttachGatedServer("结果下载", dl_port, _make_download_server)

    def _on_open():
        _print_access_urls(panel_port, panel.token, dl_port, dl.token, scan_done)

    guard = AttachGuard([panel, dl], on_all_open=_on_open)
    guard.start()

    # 已 attach 时立刻开放（不等一个轮询周期）
    if is_attached():
        guard.force_open()

    try:
        guard.wait_forever()
    finally:
        guard.stop()
        print("  HTTP 服务已全部关闭")


def _link(url: str, text: str | None = None) -> str:
    """终端超链接：OSC 8 + ANSI 下划线。不支持 OSC 8 的终端也会保留下划线。"""
    if text is None:
        text = url
    try:
        return f"\033[4m\033]8;;{url}\033\\{text}\033]8;;\033\\\033[24m"
    except Exception:
        return text


def check_deps():
    """检查必需依赖。"""
    missing = []

    try:
        import maxminddb  # noqa
    except ImportError:
        missing.append("maxminddb")

    if shutil.which("masscan") is None:
        missing.append("masscan (需手动安装: apt install masscan)")

    if missing:
        print("  📦 安装缺失依赖...")
        for dep in missing:
            if "masscan" in dep:
                print(f"  ⚠ {dep}")
            else:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", dep],
                    capture_output=True
                )
                print(f"  ✅ {dep}")
        print()


if __name__ == "__main__":
    # 进程退出时清理残留的扫描子进程。
    # 关键场景：本进程被 OOM killer 杀掉（SIGKILL 无法捕获）之外的所有退出路径，
    # 都不该让 masscan / cf-scanner 变成孤儿继续跑、继续写盘、持有已删文件句柄。
    def _cleanup_children():
        try:
            for name in ("masscan", "cf-scanner"):
                subprocess.run(["pkill", "-9", "-x", name],
                               capture_output=True, timeout=5)
        except Exception:
            pass

    import atexit as _atexit
    _atexit.register(_cleanup_children)

    def _on_signal(signum, frame):
        _cleanup_children()
        sys.exit(128 + signum)

    try:
        import signal as _signal
        for _s in (_signal.SIGTERM, _signal.SIGHUP, _signal.SIGINT):
            try:
                _signal.signal(_s, _on_signal)
            except Exception:
                pass
    except Exception:
        pass

    main()
