"""⑤ speedtest：socket 三步法测延迟+下载速度。

TCP connect → TLS handshake → HTTP GET with Range
延迟 = TCP + TLS 时间，3 次取中位数
下载 = Range 固定字节，检测 CF Challenge 页
"""
import socket
import ssl
import time
import select

from .utils import format_duration


def speedtest_ip(ip: str, port: int, sni: str = "cloudflare.com",
                 host: str = "www.cloudflare.com",
                 speed_size: int = 1048576,
                 timeout: float = 5.0,
                 proxy: str | None = None,
                 latency_only: bool = False) -> dict:
    """测单个 IP:Port 的延迟和下载速度。

    返回:
        {"ip_port", "latency_ms", "download_mbps", "error"}
    失败时 latency_ms="-", download_mbps=0
    """
    ip_port = f"{ip}:{port}"
    latencies = []

    # 3 次测延迟取中位数
    for attempt in range(3):
        lat = _measure_latency(ip, port, sni=sni, timeout=timeout, proxy=proxy)
        if lat is not None:
            latencies.append(lat)
        if len(latencies) < 3 and attempt < 2:
            time.sleep(0.2)  # 短暂间隔

    if not latencies:
        return {"ip_port": ip_port, "latency_ms": "-", "download_mbps": 0, "error": "timeout"}

    latencies.sort()
    median_lat = latencies[len(latencies) // 2]
    latency_ms = round(median_lat * 1000, 1)

    # latency_only 模式：只测延迟，不测下载速度
    if latency_only:
        return {
            "ip_port": ip_port,
            "latency_ms": latency_ms,
            "download_mbps": 0,
            "error": None,
        }

    # 测下载速度（用中位数延迟的那次连接，或新连）
    download = _measure_download(ip, port, sni=sni, host=host,
                                 speed_size=speed_size, timeout=timeout,
                                 proxy=proxy)

    return {
        "ip_port": ip_port,
        "latency_ms": latency_ms,
        "download_mbps": round(download, 2) if download > 0 else 0,
        "error": None if download > 0 else "download_failed",
    }


def _measure_latency(ip: str, port: int, sni: str = "cloudflare.com",
                     timeout: float = 5.0, proxy: str | None = None) -> float | None:
    """测 TCP+TLS 握手时间。返回秒数，失败返回 None。"""
    start = time.time()
    try:
        sock = _create_connection(ip, port, timeout=timeout, proxy=proxy)
        if sock is None:
            return None

        tcp_done = time.time()

        # TLS 握手
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            tls_sock = ctx.wrap_socket(sock, server_hostname=sni)
            tls_sock.do_handshake()
            tls_done = time.time()
            tls_sock.close()
        except Exception:
            sock.close()
            return None

        # 延迟 = TCP + TLS（完整握手成本）
        total = tls_done - start
        return total

    except Exception:
        return None


def _measure_download(ip: str, port: int, sni: str = "cloudflare.com",
                      host: str = "www.cloudflare.com",
                      speed_size: int = 1048576,
                      timeout: float = 5.0,
                      proxy: str | None = None) -> float:
    """测下载速度。返回 Mbps。"""
    try:
        sock = _create_connection(ip, port, timeout=timeout, proxy=proxy)
        if sock is None:
            return 0

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sock = ctx.wrap_socket(sock, server_hostname=sni)
        tls_sock.do_handshake()

        # HTTP GET with Range
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Range: bytes=0-{speed_size - 1}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: ASNIPtest/1.0\r\n"
            f"\r\n"
        )
        tls_sock.sendall(request.encode())

        # 读响应头
        headers = b""
        while b"\r\n\r\n" not in headers:
            chunk = tls_sock.recv(4096)
            if not chunk:
                tls_sock.close()
                return 0
            headers += chunk
            if len(headers) > 8192:  # 头太大
                tls_sock.close()
                return 0

        header_str = headers.decode("utf-8", errors="replace")

        # CF Challenge 检测
        if "Just a moment" in header_str or "challenge-form" in header_str:
            tls_sock.close()
            return 0

        # 解析 Content-Length 和状态码
        status_line = header_str.split("\r\n")[0]
        if "200" not in status_line and "206" not in status_line:
            tls_sock.close()
            return 0

        # 读响应体
        body = headers.split(b"\r\n\r\n", 1)[1]
        start_data = time.time()
        data_len = len(body)

        tls_sock.settimeout(timeout)
        while data_len < speed_size:
            try:
                chunk = tls_sock.recv(65536)
                if not chunk:
                    break
                body += chunk
                data_len += len(chunk)
            except socket.timeout:
                break

        elapsed = time.time() - start_data
        tls_sock.close()

        if elapsed <= 0 or data_len < 1024:
            return 0

        # CF Challenge 检测（检查响应体）
        body_text = body.decode("utf-8", errors="replace")
        if "Just a moment" in body_text or len(body_text) < 100:
            return 0

        # Mbps = bytes * 8 / 1000000 / seconds
        mbps = (data_len * 8) / 1_000_000 / elapsed
        return mbps

    except Exception:
        return 0


def _create_connection(ip: str, port: int, timeout: float = 5.0,
                       proxy: str | None = None) -> socket.socket | None:
    """创建 TCP 连接。支持 SOCKS5 代理。"""
    if proxy:
        # SOCKS5 代理连接
        try:
            proxy_host, proxy_port_str = proxy.split(":")
            proxy_port = int(proxy_port_str)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((proxy_host, proxy_port))

            # SOCKS5 握手
            sock.sendall(b"\x05\x01\x00")  # 仅无认证
            resp = sock.recv(2)
            if resp != b"\x05\x00":
                sock.close()
                return None

            # CONNECT 请求
            ip_bytes = bytes(int(x) for x in ip.split("."))
            port_bytes = port.to_bytes(2, "big")
            socks_cmd = b"\x05\x01\x00\x01" + ip_bytes + port_bytes
            sock.sendall(socks_cmd)

            resp = sock.recv(10)
            if resp[1] != 0x00:
                sock.close()
                return None

            return sock
        except Exception:
            return None
    else:
        # 直连
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            return sock
        except Exception:
            return None
