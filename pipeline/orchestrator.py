"""管线编排器：依次执行 ①→②→③→④→⑤→⑥。"""
import ipaddress
import json
import os
import sys
import time
from pathlib import Path

from .utils import ensure_dirs, format_duration, CACHE_DIR
from .stage1_cidr import fetch_cidrs
from .stage2_masscan import (
    generate_plan, materialize_plan, get_block_status,
    run_masscan, run_verify, DEFAULT_PORTS,
)
from .stage4_enrich import enrich_ips
from .stage5_speed import speedtest_ip
from .stage6_output import generate_report


class Orchestrator:
    """全管线编排器。"""

    def __init__(self, workdir: str = "."):
        self.workdir = os.path.abspath(workdir)
        self.cache_dir = os.path.join(self.workdir, "cache")
        self.config_dir = os.path.join(self.workdir, "config")
        self.scan_dir = os.path.join(self.workdir, "scan_data")
        self.cf_scanner = self._find_cf_scanner()
        self.proxies = None  # 查 API 用的代理
        self.verify_proxy = None  # verify 用的 SOCKS5 代理

    def _find_cf_scanner(self) -> str:
        """找 cf-scanner 二进制。"""
        candidates = [
            os.path.join(self.workdir, "cf-scanner"),
            os.path.join(self.workdir, "cf-scanner.exe"),
            "/usr/local/bin/cf-scanner",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        # 也许在 PATH 里
        import shutil
        return shutil.which("cf-scanner") or ""

    def run(self, asns: list[int], ports: str = DEFAULT_PORTS,
            force: bool = False, top_n: int | None = None,
            json_output: bool = False, speed_top: int | None = None,
            rate: int = 2000):
        """运行全管线。"""
        start_total = time.time()

        print(f"\n{'='*60}")
        print(f"  ASNIPtest 全管线 — ASN: {', '.join(str(a) for a in asns)}")
        print(f"{'='*60}\n")

        # === 1/6 ASN → CIDR ===
        print(f"[1/6 ASN→CIDR] {'='*40}")
        t0 = time.time()
        prefixes = []
        for idx, asn in enumerate(asns, 1):
            pfx = fetch_cidrs([asn], force=force, proxies=self.proxies)
            prefixes.extend(pfx)
            print(f"  ⏳ AS{asn} [{idx}/{len(asns)}] → {len(pfx)} 段")
        prefixes = sorted(set(prefixes), key=lambda x: (
            ipaddress.IPv4Network(x, strict=False).network_address))
        if not prefixes:
            print("✗ 没有可扫描的 CIDR 段，退出")
            return
        print(f"  → 共 {len(prefixes)} 个可扫描段 ({format_duration(time.time()-t0)})")
        print()

        # === 2/6 masscan + 3/6 verify ===
        print(f"[2/6 masscan + 3/6 verify] {'='*40}")
        t1 = time.time()

        # 生成 Plan
        plan = generate_plan(asns[0] if len(asns) == 1 else asns[0],
                             prefixes, ports=ports)
        # 写入 plan 和各 block CIDR 文件
        os.makedirs(self.scan_dir, exist_ok=True)
        identity = plan["resume_identity"]
        identity_str = json.dumps(identity, sort_keys=True)
        import hashlib
        plan["resume_identity"]["plan_hash"] = hashlib.sha256(
            identity_str.encode()
        ).hexdigest()[:16]

        plan_path = os.path.join(self.scan_dir, "scan_plan.json")
        tmp_path = plan_path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(plan, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, plan_path)

        # 写各 block CIDR 文件
        total_blocks = (len(prefixes) + 49) // 50
        for i in range(0, len(prefixes), 50):
            chunk = prefixes[i:i + 50]
            blk_idx = i // 50 + 1
            cidrs_file = os.path.join(self.scan_dir, f"block_{blk_idx:03d}_cidrs.txt")
            with open(cidrs_file, "w") as f:
                f.write("\n".join(chunk) + "\n")
        print(f"  共 {total_blocks} 块（{len(prefixes)} 段），见 {self.scan_dir}/block_0*.txt")

        # 检查各 block 状态（Resume）
        statuses = get_block_status(self.scan_dir, plan)
        all_ips = []  # 收集所有已验证的 IP:Port
        total_blocks = len(statuses)
        block_done = 0
        bar_width = 24
        last_len = 0

        for st in statuses:
            try:
                blk_idx = st["index"]
                state = st["state"]
                skip = False

                if state == "done":
                    cf_file = os.path.join(self.scan_dir, f"block_{blk_idx:03d}_cf.txt")
                    if os.path.exists(cf_file):
                        with open(cf_file) as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    all_ips.append(line)
                    block_done += 1
                    skip = True
                else:
                    # 跑 masscan（如果没扫过）
                    if state == "pending":
                        cidrs_file = st["cidrs_file"]
                        ok, actual_kpps = run_masscan(
                            blk_idx, cidrs_file, ports,
                            self.scan_dir, rate=rate)
                        # rate 自适应（最小 2000，最大 5000）
                        if actual_kpps > 0:
                            if actual_kpps >= rate * 0.9 and rate < 5000:
                                rate = rate + 1000
                                print(f"  ↗ 自适应提速 → rate={rate} (实际 {actual_kpps:.1f} kpps)")
                            elif actual_kpps < rate * 0.7 and rate > 2000:
                                rate = rate - 1000
                                print(f"  ↘ 自适应降速 → rate={rate} (实际 {actual_kpps:.1f} kpps)")
                        if not ok:
                            block_done += 1
                            skip = True

                    if not skip and state in ("pending", "verify_only", "verify_partial"):
                        if self.cf_scanner:
                            ok = run_verify(blk_idx, self.scan_dir, self.cf_scanner,
                                           proxy=self.verify_proxy)
                        else:
                            ok = False
                        if not ok:
                            block_done += 1
                            skip = True

                if not skip:
                    # 收集结果
                    cf_file = os.path.join(self.scan_dir, f"block_{blk_idx:03d}_cf.txt")
                    if os.path.exists(cf_file):
                        with open(cf_file) as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    all_ips.append(line)
                    block_done += 1

            except KeyboardInterrupt:
                print("\n  用户中断，保留已完成数据")
                break

            # 进度条（覆盖上一行）
            pct = block_done / total_blocks
            filled = int(bar_width * pct)
            bar = "█" * filled + " " * (bar_width - filled)
            sys.stdout.write("\r" + " " * last_len + "\r")
            line = f"  进度: {block_done}/{total_blocks} ({pct*100:.0f}%) |{bar}|"
            sys.stdout.write(line)
            sys.stdout.flush()
            last_len = len(line)

        sys.stdout.write("\n")
        sys.stdout.flush()
        print(f"  共 {total_blocks} 块，见 {self.scan_dir}/block_0*.txt")
        print()

        # 解析 verify 结果（CSV 格式：ip,port,colo,cfray,status,conf）
        verified_ips = []
        for item in all_ips:
            line = item.strip()
            if not line or line.startswith("ip,"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                ip = parts[0].strip()
                port = parts[1].strip()
                if ip and port:
                    verified_ips.append(f"{ip}:{port}")

        print(f"\n  → 共 {len(verified_ips)} 个已验证 IP ({format_duration(time.time()-t1)})")
        print()

        if not verified_ips:
            print("  ⚠ 没有验证通过的 IP")
            return

        # === 4/6 enrich ===
        print(f"[4/6 enrich] {'='*40}")
        t2 = time.time()
        bar_width = 24
        last_len = 0
        total_enrich = len(verified_ips)

        def _enrich_progress(done: int, total: int):
            nonlocal last_len
            pct = done / total if total else 1
            filled = int(bar_width * pct)
            bar = "█" * filled + " " * (bar_width - filled)
            sys.stdout.write("\r" + " " * last_len + "\r")
            line = f"  补充元数据: {done}/{total} ({pct*100:.0f}%) |{bar}|"
            sys.stdout.write(line)
            sys.stdout.flush()
            last_len = len(line)

        enriched = enrich_ips(
            verified_ips,
            proxies=self.proxies,
            on_progress=lambda done: _enrich_progress(done, total_enrich),
        )
        sys.stdout.write("\n")
        sys.stdout.flush()

        cf_official = sum(1 for r in enriched if r.get("is_cf_official"))
        print(f"  → {len(enriched)} 条补充元数据 ({format_duration(time.time()-t2)})")
        print(f"  → 其中 CF 官方 ASN: {cf_official} 条")
        print()

        # === 5/6 speedtest ===
        print(f"[5/6 speedtest] {'='*40}")
        t3 = time.time()

        # 只测非 CF 官方 IP
        to_test = [r for r in enriched if not r.get("is_cf_official")]
        if speed_top and speed_top > 0:
            to_test = to_test[:speed_top]

        speed_results = []
        total = len(to_test)
        if total == 0:
            print("  → 无需要测速的 IP")
        else:
            bar_width = 24
            last_len = 0
            for i, row in enumerate(to_test, 1):
                ip_port = row["ip_port"]
                ip, port_str = ip_port.rsplit(":", 1)
                port = int(port_str)

                sr = speedtest_ip(ip, port, timeout=5.0, proxy=self.verify_proxy)
                speed_results.append(sr)

                pct = i / total
                filled = int(bar_width * pct)
                bar = "█" * filled + " " * (bar_width - filled)

                sys.stdout.write("\r" + " " * last_len + "\r")
                line = f"  测速: {i}/{total} ({pct*100:.0f}%) |{bar}|"
                sys.stdout.write(line)
                sys.stdout.flush()
                last_len = len(line)

            sys.stdout.write("\n")
            sys.stdout.flush()

        print(f"  → 测速完成 ({format_duration(time.time()-t3)})")
        print()

        # === 6/6 合并数据 + 输出报告 ===
        print(f"[6/6 output] {'='*40}")
        t4 = time.time()

        # 按 ip_port 合并 enrich + speed
        speed_map = {r["ip_port"]: r for r in speed_results}
        merged = []
        from .utils import classify_ip_type, load_cf_official_asns
        cf_asns = load_cf_official_asns()
        for row in enriched:
            ip_port = row["ip_port"]
            sp = speed_map.get(ip_port, {})
            org = row.get("org", "-")
            asn = row.get("asn", "-")
            # CF 官方走 is_cf_official，不在 IP 类型中标
            if row.get("is_cf_official") or asn in cf_asns:
                ip_type = "CF官方"
            else:
                ip_type = classify_ip_type(org, asn)
            merged.append({
                "ip_port": ip_port,
                "asn": row["asn"],
                "country": row["country"],
                "country_code": row.get("country_code", "-"),
                "region_name": row.get("region_name", "-"),
                "city": row.get("city", "-"),
                "org": row["org"],
                "is_cf_official": row["is_cf_official"],
                "ip_type": ip_type,
                "latency_ms": sp.get("latency_ms", "-"),
                "download_mbps": sp.get("download_mbps", 0),
                "tls": sp.get("tls", "-") if sp.get("tls") else "-",
                "alpn": sp.get("alpn", "-") if sp.get("alpn") else "-",
                "verify_reason": "-",
                "confidence": "-",
                "source": row.get("source", "-"),
            })

        from asnip import _get_public_ip
        public_ip = _get_public_ip() or "-"

        stats = generate_report(
            merged,
            output_dir=self.workdir,
            top_n=top_n,
            keep_cf_official=False,
            json_output=json_output,
            public_ip=public_ip,
        )

        total_elapsed = time.time() - start_total
        print(f"  ✅ 报告已生成: {stats['csv_path']}")
        if stats["json_path"]:
            print(f"  ✅ JSON 已生成: {stats['json_path']}")
        print(f"  📊 总计: {stats['total_input']} 输入 → "
              f"{stats['cf_official']} CF官方剔除 → "
              f"{stats['with_speed']} 有测速 → "
              f"{stats['final_output']} 最终输出")
        print(f"\n{'='*60}")
        print(f"  总耗时: {format_duration(total_elapsed)}")
        print(f"{'='*60}")
