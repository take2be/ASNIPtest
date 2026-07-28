#!/usr/bin/env python3
"""
API 精筛 — 调用 api.090227.xyz/check 验证 CF 节点可用性
分片流式，默认并发 32
"""
import argparse, urllib.request, json, time, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_single(line):
    """Check single IP:port via CF proxy probe, return cfnb-format result or None"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    ip_port = parts[0] if parts else line
    try:
        url = f"https://api.090227.xyz/check?proxyip={ip_port}"
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json",
            "Origin": "https://090227.xyz",
        }
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if not data.get("success"):
                return None
            # Get actual CF exit info from probe_results
            pr = data.get("probe_results", {})
            exit_info = pr.get("ipv4", {}).get("exit") or pr.get("ipv6", {}).get("exit") or {}
            colo = exit_info.get("colo", data.get("colo", ""))
            country = exit_info.get("country", "")
            region = exit_info.get("region", "")
            asn = exit_info.get("asn", data.get("asn", ""))
            # cfnb format: IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN
            ip, port = ip_port.rsplit(":", 1)
            return f"{ip},{port},TRUE,{colo},{country},{region},,,AS{asn}"
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--api", default="https://api.090227.xyz/check")
    parser.add_argument("--chunk", type=int, default=5000)
    parser.add_argument("--concurrent", type=int, default=32)
    args = parser.parse_args()

    with open(args.input) as f:
        all_lines = [l for l in f if l.strip() and not l.startswith("#")]

    total = len(all_lines)
    passed = 0
    failed = 0
    start = time.time()

    with open(args.output, "w") as out:
        out.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for i in range(0, total, args.chunk):
            chunk = all_lines[i:i + args.chunk]
            with ThreadPoolExecutor(max_workers=args.concurrent) as ex:
                futures = {ex.submit(check_single, line): line for line in chunk}
                for f in as_completed(futures):
                    result = f.result()
                    if result:
                        out.write(result + "\n")
                        passed += 1
                    else:
                        failed += 1
            elapsed = time.time() - start
            done = i + len(chunk)
            rate = done / elapsed if elapsed > 0 else 0
            eta = (total - done) / rate if rate > 0 else 0
            sys.stderr.write(f"\r{done}/{total} | 通过 {passed} | {rate:.1f}/s | ETA {eta/60:.1f}m   ")
            sys.stderr.flush()

    elapsed = int(time.time() - start)
    sys.stderr.write(f"\n完成 | {elapsed//60}min | 通过 {passed}/{total}\n")

if __name__ == "__main__":
    main()
