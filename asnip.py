#!/usr/bin/env python3
"""ASNIPtest CLI — 一键 ASN 反代 IP 优选工具。

用法:
  asnip scan              # 交互模式
  asnip scan 13335,209554 # 直接指定 ASN
"""
import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler


class _DownloadHandler(SimpleHTTPRequestHandler):
    """结果文件下载处理器：CSV/JSON 自动作为附件下载。"""

    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".csv": "text/csv",
        ".json": "application/json",
    }

    def end_headers(self):
        path = self.translate_path(self.path)
        _, ext = os.path.splitext(path)
        if ext.lower() in (".csv", ".json"):
            self.send_header("Content-Disposition",
                             f"attachment; filename={os.path.basename(path)}")
        super().end_headers()

    def log_message(self, format, *args):
        pass  # 安静运行，不刷日志

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
        subparser.add_argument("--port", type=int, default=8080,
                              help="HTTP 服务端口（默认 8080）")
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
        subparser.add_argument("--rate", type=int, default=2000,
                              help="masscan 扫描速率 pkts/s（默认 2000，小鸡建议800-1500）")
    
    # scan 子命令
    scan_parser = subparsers.add_parser("scan", help="扫描 ASN")
    add_common_args(scan_parser)
    
    # ips 子命令
    ips_parser = subparsers.add_parser("ips", help="扫描 ASN (ips 别名)")
    add_common_args(ips_parser)

    args = parser.parse_args()

    os.chdir(PROJECT_DIR)

    if args.action in ("scan", "ips"):
        cmd_scan(args)
    elif args.action is None:
        parser.print_help()
    else:
        print(f"未知操作: {args.action}")


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

    # ---- ASN/CIDR 输入 ----
    asns = []
    if args.asn and args.asn[0]:
        raw = " ".join(args.asn)
    else:
        raw = input("  输入 ASN（多个用逗号分隔，如: 13335,209554）: ").strip()
    asns = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if token.upper().startswith("AS"):
            token = token[2:]
        asns.append(int(token))
    if not asns:
        print("  ✗ 未输入有效 ASN")
        return
    print(f"  → ASN: {', '.join('AS' + str(a) for a in asns)}")
    print()

    # ---- 端口输入 ----
    ports = args.ports
    if not ports:
        raw = input(f"  输入端口（回车默认: {DEFAULT_PORTS}）: ").strip()
        ports = raw if raw else DEFAULT_PORTS
    print(f"  → 端口: {ports}")
    print()

    # ---- 代理（仅 WSL）----
    is_wsl = _is_wsl()
    proxies = None
    verify_proxy = None

    if is_wsl:
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

    # ---- 测速询问 ----
    do_speed = False
    if not args.top and not args.json:
        use_speed = input("  是否测速？(y/n，默认跳过): ").strip().lower()
        do_speed = use_speed in ("y", "yes")
    speed_top = None if not do_speed else 0

    # ---- 运行管线（直接开始，无确认）----
    from pipeline.orchestrator import Orchestrator

    app = Orchestrator()
    app.proxies = proxies
    app.verify_proxy = verify_proxy

    if args.daemon:
        # 后台循环：直到 report.csv 生成才退出
        import signal
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        import atexit
        @atexit.register
        def _on_exit():
            print("\n  守护进程退出")
        while True:
            app.run(
                asns=asns,
                ports=ports,
                force=False,
                top_n=args.top,
                speed_top=0 if args.top or args.json else 0,
                json_output=args.json,
                rate=args.rate,
            )
            report_csv = os.path.join(PROJECT_DIR, "report.csv")
            if os.path.exists(report_csv) and os.path.getsize(report_csv) > 100:
                print("\n  ✅ report.csv 已生成，守护进程退出")
                break
            print("\n  报告未生成，10 秒后自动续跑...")
            time.sleep(10)
        return

    app.run(
        asns=asns,
        ports=ports,
        force=args.force,
        top_n=args.top,
        speed_top=speed_top,
        json_output=args.json,
        rate=args.rate,
    )

    # ---- 启动结果 HTTP 服务 ----
    report_csv = os.path.join(PROJECT_DIR, "report.csv")
    if os.path.exists(report_csv) and os.path.getsize(report_csv) > 100:
        _serve_results(port=args.port)


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


def _serve_results(port: int = 8080):
    """启动 HTTP 服务提供结果文件，输出 LAN + 公网地址。"""
    results_dir = PROJECT_DIR
    os.chdir(results_dir)

    # 获取 LAN IP
    lan_ip = _get_lan_ip()

    # 异步获取公网 IP
    public_ip = None
    def _fetch_public():
        nonlocal public_ip
        public_ip = _get_public_ip()
    t = threading.Thread(target=_fetch_public, daemon=True)
    t.start()

    # 启动 HTTP 服务（后台线程）
    server = HTTPServer(("0.0.0.0", port), _DownloadHandler)
    t_server = threading.Thread(target=server.serve_forever, daemon=True)
    t_server.start()

    # 等待公网 IP 获取（最多等 3s）
    t.join(timeout=3)

    print()
    print("=" * 56)
    print("  📡 结果已可通过 HTTP 访问")
    print("=" * 56)
    print()

    # 本地文件路径
    csv_path = os.path.join(results_dir, "report.csv")
    json_path = os.path.join(results_dir, "report.json")
    _p_label = "  📄 "
    print(f"{_p_label}CSV 报告:  {csv_path}")
    if os.path.exists(json_path):
        print(f"{_p_label}JSON 报告: {json_path}")
    print()

    # HTTP 下载链接（局域网 / 公网）
    if lan_ip:
        url_local_csv = f"http://{lan_ip}:{port}/report.csv"
        url_local_json = f"http://{lan_ip}:{port}/report.json"
        print(f"  🌐 局域网地址:  {_link(url_local_csv, url_local_csv)}")
        print(f"                   {_link(url_local_json, url_local_json)}")

    if public_ip:
        url_pub_csv = f"http://{public_ip}:{port}/report.csv"
        url_pub_json = f"http://{public_ip}:{port}/report.json"
        print(f"  🌍 公网地址:    {_link(url_pub_csv, url_pub_csv)}")
        print(f"                   {_link(url_pub_json, url_pub_json)}")
    else:
        print(f"  🌍 公网地址:    获取失败（需公网 IP 和端口放行）")

    print()
    print("  提示：若浏览器打不开，请确认 VPS 防火墙已放行"
          f" {port}/tcp。")
    print(f"  按 Ctrl+C 停止服务")
    print()

    # 保持主进程
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  服务已停止")
        server.shutdown()


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
        import dns.resolver  # noqa
    except ImportError:
        missing.append("dnspython")

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
    main()
