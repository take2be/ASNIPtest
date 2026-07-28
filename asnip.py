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
    parser.add_argument("action", nargs="?", default="scan",
                        help="操作: scan (默认)")
    parser.add_argument("asn", nargs="?", default="",
                        help="ASN 号（多个用逗号分隔）")
    parser.add_argument("--ports", default="",
                        help=f"端口集（默认交互输入）")
    parser.add_argument("--port", type=int, default=8080,
                        help="HTTP 服务端口（默认 8080）")
    parser.add_argument("--force", action="store_true",
                        help="忽略缓存强制刷新")
    parser.add_argument("--top", type=int, default=None,
                        help="只输出前 N 个结果")
    parser.add_argument("--json", action="store_true",
                        help="额外输出 JSON 格式报告")
    parser.add_argument("--no-deps", action="store_true",
                        help="跳过依赖检查")

    args = parser.parse_args()

    os.chdir(PROJECT_DIR)

    if args.action == "scan":
        cmd_scan(args)
    else:
        print(f"未知操作: {args.action}")
        print("用法: asnip scan [ASN...]")


def cmd_scan(args):
    """执行扫描管线。"""
    print()
    print("=" * 56)
    print("  🔍 ASNIPtest — 第三方 Cloudflare 反代 IP 优选工具")
    print("=" * 56)
    print()

    # ---- 依赖检查 ----
    if not args.no_deps:
        check_deps()

    # ---- 系统信息 ----
    _print_system_info()
    print()

    # ---- ASN/CIDR 输入 ----
    asns = []
    if args.asn:
        raw = args.asn
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

    app.run(
        asns=asns,
        ports=ports,
        force=args.force,
        top_n=args.top,
        speed_top=speed_top,
        json_output=args.json,
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


def _estimate_prefixes(asn: int, proxies: dict | None = None) -> int:
    """预估 ASN 的 CIDR 段数（快速试探）。"""
    try:
        from pipeline.stage1_cidr import _fetch_single
        prefixes = _fetch_single(asn, force=True, proxies=proxies)
        return len(prefixes) if prefixes else 0
    except Exception:
        return 0


def _serve_results(port: int = 8080):
    """启动 HTTP 服务提供结果文件，输出 LAN + 公网地址。"""
    results_dir = PROJECT_DIR
    os.chdir(results_dir)

    # 获取 LAN IP
    lan_ip = _get_lan_ip()

    # 获取公网 IP（异步，不阻塞）
    public_ip = None
    def _fetch_public():
        nonlocal public_ip
        try:
            import urllib.request
            with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
                public_ip = r.read().decode().strip()
        except Exception:
            pass
    t = threading.Thread(target=_fetch_public, daemon=True)
    t.start()

    # 启动 HTTP 服务（后台线程）
    handler = SimpleHTTPRequestHandler

    server = HTTPServer(("0.0.0.0", port), handler)
    t_server = threading.Thread(target=server.serve_forever, daemon=True)
    t_server.start()

    # 等待公网 IP 获取（最多等 3s）
    t.join(timeout=3)

    print()
    print("=" * 56)
    print("  📡 结果已可通过 HTTP 访问")
    print("=" * 56)
    print()

    print(f"  📄 CSV 报告: {os.path.join(results_dir, 'report.csv')}")
    if os.path.exists(os.path.join(results_dir, "report.json")):
        print(f"  📄 JSON 报告: {os.path.join(results_dir, 'report.json')}")

    print()
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
    print(f"  按 Ctrl+C 停止服务")
    print()

    # 保持主进程
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  服务已停止")
        server.shutdown()


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


def _link(url: str, text: str | None = None) -> str:
    """终端 ANSI 超链接（OSC 8）。不支持时降级为普通 URL。"""
    if text is None:
        text = url
    try:
        return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"
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
