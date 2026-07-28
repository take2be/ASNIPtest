"""③ verify 对接模块 — 调用 Go cf-scanner 二进制进行 CF 反代验证

通过子进程调用 Go 编译的 cf-scanner，输入 IP:Port 列表，输出验证结果。
"""

import os
import sys
import subprocess
import json
import time
from pathlib import Path

from .utils import log, PROJECT_ROOT, atomic_write, RateCounter

# cf-scanner 二进制路径
CF_SCANNER_PATH = PROJECT_ROOT / "cf-scanner"


def _find_go_binary() -> str:
    """查找 cf-scanner 二进制路径"""
    # 优先项目目录
    candidates = [
        str(PROJECT_ROOT / "cf-scanner"),
        str(PROJECT_ROOT / "cf-scanner.exe"),
        "/usr/local/bin/cf-scanner",
        "/usr/bin/cf-scanner",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return str(CF_SCANNER_PATH)


def run_verify(
    input_file: str,
    output_file: str = None,
    concurrency: int = 200,
    proxy: str = None,
    sni: str = "cloudflare.com",
    host: str = "www.cloudflare.com",
    timeout_sec: int = 10,
    connect_timeout_sec: int = 5,
    verify_mode: str = "hybrid",
    plan_dir: str = None,
) -> dict:
    """调用 Go cf-scanner 验证 CF 反代 IP

    Args:
        input_file: 输入文件路径（每行 IP:port）
        output_file: 输出文件路径（默认自动生成）
        concurrency: 并发数（直连建议 500~5000，代理建议 ≤200）
        proxy: SOCKS5 代理地址（如 "127.0.0.1:10808"）
        sni: TLS SNI
        host: HTTP Host 头
        timeout_sec: TLS/HTTP 总超时秒数
        connect_timeout_sec: TCP 连接超时秒数
        verify_mode: 验证插件 (hybrid/tls/http)
        plan_dir: 工作目录（存放产物）

    Returns:
        {"returncode": int, "output_file": str, "elapsed": float, "stats": str}
    """
    binary = _find_go_binary()

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"输入文件不存在: {input_file}")

    if output_file is None and plan_dir:
        ts = time.strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(plan_dir, f"verify_result_{ts}.csv")

    cmd = [binary, "-i", input_file]

    if output_file:
        cmd.extend(["-o", output_file])
    cmd.extend(["-c", str(concurrency)])
    cmd.extend(["-sni", sni])
    cmd.extend(["-host", host])
    cmd.extend(["-timeout", f"{timeout_sec}s"])
    cmd.extend(["-connect-timeout", f"{connect_timeout_sec}s"])
    cmd.extend(["-verify-mode", verify_mode])
    cmd.extend(["-format", "csv"])
    cmd.extend(["-fields", "ip,port,cfray,status,conf"])

    # 背压（直连且高并发才开）
    if concurrency >= 1000 and not proxy:
        cmd.append("-backpressure")

    if proxy:
        cmd.extend(["-proxy", proxy])
        # 代理模式限制并发
        if concurrency > 500:
            log.warning(f"  ⚠️ 代理模式并发建议 ≤500，当前 {concurrency}，自动降至 200")
            # 替换并发参数
            for i, arg in enumerate(cmd):
                if arg == "-c":
                    cmd[i + 1] = "200"
                    break

    if plan_dir:
        cmd.extend(["-plan-dir", plan_dir])

    log.info(f"  🚀 启动 cf-scanner: {os.path.basename(binary)}")
    log.info(f"  📥 输入: {os.path.basename(input_file)} | 并发: {concurrency} | 插件: {verify_mode}")
    log.info(f"  🔌 出口: {'代理 ' + proxy if proxy else '直连'}")

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=3600
        )
        elapsed = time.monotonic() - start

        # 提取统计行
        stats_lines = []
        for line in result.stdout.splitlines():
            if any(kw in line for kw in ("结果:", "PASS", "FAIL", "UNK", "最终", "耗时")):
                stats_lines.append(line)
        stats = "\n".join(stats_lines) if stats_lines else result.stdout[-500:]

        if result.returncode == 0:
            log.info(f"  ✅ verify 完成 ({elapsed:.1f}s)")
        else:
            log.warning(f"  ⚠️ cf-scanner 退出码={result.returncode}")

        if result.stderr:
            for line in result.stderr.strip().splitlines()[-5:]:
                log.info(f"  ⚠️ {line}")

        return {
            "returncode": result.returncode,
            "output_file": output_file or "",
            "elapsed": elapsed,
            "stats": stats,
            "stdout_tail": result.stdout[-1000:] if len(result.stdout) > 1000 else result.stdout,
        }

    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        log.error(f"  ❌ cf-scanner 超时 ({elapsed:.1f}s)")
        return {"returncode": -1, "output_file": "", "elapsed": elapsed, "stats": "TIMEOUT", "stdout_tail": ""}
    except FileNotFoundError:
        log.error(f"  ❌ cf-scanner 未找到，请先编译: {binary}")
        log.error(f"     编译: cd cf-scanner-src && go build -o ../cf-scanner .")
        return {"returncode": -2, "output_file": "", "elapsed": 0, "stats": "BINARY_NOT_FOUND", "stdout_tail": ""}


# ── 独立测试 ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python -m pipeline.step3_verify <input_file> [--proxy addr:port]")
        sys.exit(1)

    input_file = sys.argv[1]
    proxy = None
    if "--proxy" in sys.argv:
        idx = sys.argv.index("--proxy")
        if idx + 1 < len(sys.argv):
            proxy = sys.argv[idx + 1]

    result = run_verify(
        input_file=input_file,
        proxy=proxy,
        concurrency=200 if proxy else 2000,
    )

    print(f"\n结果:")
    print(f"  返回码: {result['returncode']}")
    print(f"  耗时:   {result['elapsed']:.1f}s")
    print(f"  输出:   {result['output_file']}")
    if result['stats']:
        print(f"  统计:\n{result['stats']}")
