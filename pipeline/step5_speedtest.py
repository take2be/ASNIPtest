"""⑤ speedtest — TCP+TLS 延迟 + HTTP Range 下载测速

纯 Python socket 三步法（TCP→TLS→HTTP GET Range），无外部依赖。
"""

import os
import sys
import time
import socket
import ssl
import threading
import statistics
from pathlib import Path

from .utils import log, CACHE_DIR, atomic_write, clear_proxy_env, RateCounter

# ── 常量 ──────────────────────────────────────────────────────────────
DEFAULT_SPEED_SIZE = 1_048_576  # 1MB
DEFAULT_TIMEOUT = 5  # 秒
SPEED_SCHEMA = 1

# 手动构造 HTTP GET 请求（免依赖）
def _build_http_request(host: str, range_size: int = None) -> bytes:
    """构造 HTTP GET 请求"""
    if range_size:
        return (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Range: bytes=0-{range_size - 1}\r\n"
            f"User-Agent: ASNIPtest/1.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
    else:
        return (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: ASNIPtest/1.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()


def _check_cf_challenge(data: bytes) -> bool:
    """检测 CF Challenge 页"""
    # 特征: "Just a moment..." / "Checking your browser" / "cf-browser-verification"
    indicators = [b"Just a moment", b"Checking your browser", b"cf-browser-verification"]
    return any(ind in data for ind in indicators)


def measure_latency(ip: str, port: int, timeout: int = DEFAULT_TIMEOUT,
                    sni: str = "cloudflare.com") -> float | None:
    """测 TCP+TLS 延迟（单次）

    Returns: 延迟毫秒数，失败返回 None
    """
    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            tcp_done = time.monotonic()
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                tls_done = time.monotonic()
                latency_ms = (tls_done - start) * 1000
                return latency_ms
    except Exception:
        return None


def measure_speed(ip: str, port: int, timeout: int = DEFAULT_TIMEOUT,
                  speed_size: int = DEFAULT_SPEED_SIZE,
                  sni: str = "cloudflare.com",
                  host: str = "www.cloudflare.com") -> tuple[float | None, float | None, str]:
    """测延迟+下载速度（单次）

    Returns:
        (latency_ms, download_mbps, error_or_empty)
        - latency_ms: TCP+TLS 延迟毫秒
        - download_mbps: 下载速度 Mbps
        - error: 错误描述或 ""
    """
    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            tcp_time = time.monotonic()
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                tls_time = time.monotonic()
                latency_ms = (tls_time - start) * 1000
                # Close the timing socket, reopen for download
                # Actually, reuse the same connection for HTTP

        # 第二次连接做下载（保持干净）
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            ctx2 = ssl.create_default_context()
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            with ctx2.wrap_socket(sock, server_hostname=sni) as tls:
                req = _build_http_request(host, speed_size)
                tls.sendall(req)

                # 读响应
                data = b""
                while True:
                    try:
                        chunk = tls.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                        # 超过了就停
                        if len(data) > speed_size + 4096:  # 留头部余量
                            break
                    except socket.timeout:
                        break

            download_end = time.monotonic()

        # 检查 CF Challenge
        if _check_cf_challenge(data):
            return latency_ms, 0.0, "CF_CHALLENGE"

        # 提取 Body（跳过 HTTP 头）
        body_start = data.find(b"\r\n\r\n")
        if body_start < 0:
            return latency_ms, 0.0, "NO_HTTP_HEADER"

        headers = data[:body_start].decode(errors="replace")
        body = data[body_start + 4:]

        # 检查 Content-Length vs Range
        actual_bytes = len(body)
        download_time = download_end - tls_time

        if actual_bytes < speed_size * 0.9:
            # 没取到足够数据
            if actual_bytes == 0:
                return latency_ms, 0.0, "EMPTY_BODY"
            return latency_ms, 0.0, f"SHORT_BODY({actual_bytes})"

        download_mbps = (actual_bytes * 8) / (download_time * 1_000_000)
        return latency_ms, round(download_mbps, 2), ""

    except socket.timeout:
        return None, 0.0, "TIMEOUT"
    except ConnectionRefusedError:
        return None, 0.0, "REFUSED"
    except Exception as e:
        return None, 0.0, str(e)[:40]


def speedtest_block(
    ip_ports: list[str],
    output_path: str = None,
    workers: int = 16,
    timeout: int = DEFAULT_TIMEOUT,
    speed_size: int = DEFAULT_SPEED_SIZE,
    top_n: int = 0,
    proxy: str = None,
) -> dict:
    """批量测速一个 Block 的 IP:Port

    Args:
        ip_ports: ["ip:port", ...]
        output_path: 输出文件路径
        workers: 并发 worker 数
        timeout: 单次超时秒数
        speed_size: 下载字节数
        top_n: 0=全测，N=只测前 N
        proxy: SOCKS5 代理地址（可选，默认直连）

    Returns:
        {"results": [(ip,port,latency_ms,download_mbps,error)], "elapsed": float}
    """
    if top_n > 0:
        ip_ports = ip_ports[:top_n]

    clear_proxy_env()

    results = []
    lock = threading.Lock()
    counter = RateCounter()

    def worker():
        while True:
            with lock:
                if not ip_ports:
                    break
                item = ip_ports.pop(0)
            ip, port_str = item.rsplit(":", 1)
            port = int(port_str)
            lat, mbps, err = measure_speed(ip, port, timeout, speed_size)
            with lock:
                results.append((ip, port, lat, mbps, err))
                counter.tick()
                done = len(results)
                if done % 50 == 0:
                    log.info(f"  📊 测速: {done}, {counter.rate:.0f}/s, 延迟={lat or 0:.0f}ms")

    start = time.monotonic()

    threads = []
    for _ in range(min(workers, len(ip_ports))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    elapsed = time.monotonic() - start

    # 写结果文件
    if output_path:
        lines = []
        for ip, port, lat, mbps, err in results:
            lat_str = f"{lat:.1f}" if lat is not None else "-"
            lines.append(f"{ip}:{port} {lat_str} {mbps} {err}")
        atomic_write(output_path, "\n".join(lines) + "\n")
        log.info(f"  📄 {os.path.basename(output_path)}: {len(lines)} 行")

    # 统计
    valid_lats = [r[2] for r in results if r[2] is not None]
    valid_speeds = [r[3] for r in results if r[3] > 0]
    cf_blocked = sum(1 for r in results if r[4] == "CF_CHALLENGE")
    timed_out = sum(1 for r in results if r[4] == "TIMEOUT")
    errors = sum(1 for r in results if r[4] and r[4] != "")

    stats = {
        "total": len(results),
        "valid_latency": len(valid_lats),
        "valid_speed": len(valid_speeds),
        "median_latency_ms": round(statistics.median(valid_lats), 1) if valid_lats else None,
        "mean_download_mbps": round(statistics.mean(valid_speeds), 2) if valid_speeds else None,
        "max_download_mbps": round(max(valid_speeds), 2) if valid_speeds else None,
        "cf_challenge": cf_blocked,
        "timed_out": timed_out,
        "errors": errors,
    }

    log.info(f"  📊 结果: {stats['total']} IPs, "
             f"延迟中位数={stats['median_latency_ms']}ms, "
             f"平均速度={stats['mean_download_mbps']}Mbps, "
             f"最快={stats['max_download_mbps']}Mbps")

    return {
        "results": results,
        "output_path": output_path or "",
        "elapsed": elapsed,
        "stats": stats,
    }


# ── 独立测试 ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_targets = ["1.1.1.1:443", "8.8.8.8:443"]
    result = speedtest_block(test_targets, workers=2)
    print(f"\n结果: {json.dumps(result['stats'], indent=2)}")
