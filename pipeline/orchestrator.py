"""管线编排器：依次执行 ①→②→③→④→⑤→⑥。"""
import ipaddress
import json
import os
import sys
import time
from datetime import datetime
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
from . import progress as progress_state


def _purge_expired_cidrs(scan_dir: str, ttl_seconds: int = 172800):
    """删除超过 TTL 的 CIDR 文件（block_NNN_cidrs.txt）。
    CIDR 文件保留 48h（172800s），其余缓存文件保留 24h。
    """
    if not os.path.isdir(scan_dir):
        return
    now = time.time()
    removed = 0
    for name in os.listdir(scan_dir):
        if not name.endswith("_cidrs.txt"):
            continue
        fpath = os.path.join(scan_dir, name)
        if not os.path.isfile(fpath):
            continue
        try:
            mtime = os.path.getmtime(fpath)
            if now - mtime >= ttl_seconds:
                os.remove(fpath)
                removed += 1
        except OSError:
            pass
    if removed:
        print(f"  🧹 清理过期 CIDR 文件: {removed} 个 (TTL={ttl_seconds}s)")


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
        install_src = os.path.join(
            os.path.expanduser("~/.asnip"), "src")
        candidates = [
            os.path.join(self.workdir, "cf-scanner"),
            os.path.join(self.workdir, "cf-scanner.exe"),
            os.path.join(install_src, "cf-scanner"),
            os.path.join(install_src, "cf-scanner.exe"),
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
            rate: int = 2000, cidrs: list[str] | None = None):
        """运行全管线。

        cidrs: 非空时直接扫给定 IP 段（跳过 ① ASN→CIDR 拉取）；
               此时 asns 应为空列表。
        """
        start_total = time.time()
        # 目标标识：CIDR 优先（/ 换 _），否则 ASN 列表
        target_label = (cidrs[0].replace("/", "_")
                        if cidrs else ",".join(str(a) for a in asns))
        target_disp = (", ".join(cidrs) if cidrs
                       else ", ".join("AS" + str(a) for a in asns))
        try:
            progress_state.reset()
            progress_state.stage("cidr",
                                 asn=[target_label] if target_label else [],
                                 ports=ports, rate=rate)
        except Exception:
            pass

        # 清理过期 CIDR 文件（48h = 172800s TTL）
        _purge_expired_cidrs(self.scan_dir, ttl_seconds=172800)

        print(f"\n{'='*60}")
        print(f"  ASNIPtest 全管线 — {'IP 段' if cidrs else 'ASN'}: {target_disp}")
        print(f"{'='*60}\n")

        # === 1/6 ASN → CIDR（或直接使用给定 IP 段）===
        print(f"[1/6 {'IP段' if cidrs else 'ASN→CIDR'}] {'='*40}")
        t0 = time.time()
        prefixes = []
        if cidrs:
            # 直接扫给定 IP 段，跳过 RIPEStat/BGPView 拉取
            prefixes = list(cidrs)
            print(f"  → 直接使用 {len(prefixes)} 个 IP 段")
        else:
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

        # 生成 Plan（标识用 ASN 或 CIDR 主段）
        plan = generate_plan(target_label, prefixes, ports=ports)
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

        # 验证进度累计（跨 block）：已完成 block 的 targets + 当前 block 实时进度
        # 目的：面板 S3 与"已验证 IP"显示的是全部已做工作的累计量，
        # 而不是当前 block 的局部数据
        _verify_total = 0
        _verify_done = 0
        _verify_base = 0    # 已完成 block 的 targets 累计
        _hits_base = 0      # 已完成 block 的命中累计

        def _safe_verify_progress(done: int, total: int, hits: int):
            nonlocal _verify_total, _verify_done, _verify_base, _cur_block_targets
            nonlocal _cur_block_hits
            try:
                _cur_block_targets = max(total, 0)
                _cur_block_hits = max(hits, 0)
                # 分母：已完成块的 targets + 当前块 targets + 未开始块的预估
                # （未开始块用已知块的平均 targets 数外推，保证 S3 不会因为
                #   分母只有当前块而虚高到 100%）
                _known_blocks = _blocks_with_targets or 1
                _avg_targets = ((_verify_base + _cur_block_targets) / _known_blocks)
                _pending_blocks = max(0, total_blocks - _known_blocks)
                _verify_total = int(_verify_base + _cur_block_targets
                                    + _avg_targets * _pending_blocks)
                _verify_done = _verify_base + min(done, total)
                progress_state.verify_progress(_verify_done, _verify_total,
                                               _hits_base + _cur_block_hits)
            except Exception:
                pass

        # 当前 block 的验证 target 数 / 命中数（block 结束后计入 base）
        _cur_block_targets = 0
        _cur_block_hits = 0
        _blocks_with_targets = 0   # 已知 targets 数的 block 个数（含当前块）

        def _on_block_verify_start():
            nonlocal _blocks_with_targets
            _blocks_with_targets += 1

        def _on_block_verify_done():
            nonlocal _verify_base, _cur_block_targets, _hits_base, _cur_block_hits
            _verify_base += _cur_block_targets
            _hits_base += _cur_block_hits
            _cur_block_targets = 0
            _cur_block_hits = 0

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
                    # 跑 masscan（如果没扫过）——完全尊重用户设定的 rate，不做自适应升降
                    if state == "pending":
                        try:
                            # 进入 masscan 阶段（立即切换，让面板显示真实阶段）
                            progress_state.stage("masscan", asn=None, ports=None, rate=None)
                            # 立即初始化 total（否则面板 S2 无分母算不出进度）
                            # done 用已完成块数，避免每块开头把 S2 进度打回 0
                            progress_state.masscan(block_done, total_blocks,
                                                   found=len(all_ips))
                        except Exception:
                            pass
                        try:
                            progress_state.log(f"开始扫描 Block {blk_idx} ({st['cidrs_file']}, 端口 {ports}, 速率 {rate} pps)")
                        except Exception:
                            pass
                        cidrs_file = st["cidrs_file"]
                        ok, actual_kpps = run_masscan(
                            blk_idx, cidrs_file, ports,
                            self.scan_dir, rate=rate)
                        # 记录实际速率（仅展示用，不改 rate）
                        try:
                            progress_state.log(f"Block {blk_idx} 扫描完成, 实际速率 {actual_kpps:.1f} kpps")
                        except Exception:
                            pass
                        if not ok:
                            block_done += 1
                            skip = True

                    if not skip and state in ("pending", "verify_only", "verify_partial"):
                        if self.cf_scanner:
                            _on_block_verify_start()
                            ok = run_verify(blk_idx, self.scan_dir, self.cf_scanner,
                                           proxy=self.verify_proxy,
                                           progress_cb=lambda d, t, h: _safe_verify_progress(d, t, h))
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
                    # 当前 block 验证完成，targets 计入累计基数
                    _on_block_verify_done()

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
            # 网页进度（仅写状态，不影响扫描）
            try:
                progress_state.masscan(block_done, total_blocks, found=len(all_ips))
            except Exception:
                pass

        sys.stdout.write("\n")
        sys.stdout.flush()
        print(f"  共 {total_blocks} 块，见 {self.scan_dir}/block_0*.txt")
        print()

        # 解析 verify 结果（CSV 格式：ip,port,colo,cfray,status,conf）
        verify_result = {}
        verified_ips = []
        colo_map = {}
        for item in all_ips:
            line = item.strip()
            if not line or line.startswith("ip,"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                ip = parts[0].strip()
                port = parts[1].strip()
                colo = parts[2].strip() if len(parts) >= 3 else ""
                if ip and port:
                    ip_port = f"{ip}:{port}"
                    verified_ips.append(ip_port)
                    if colo:
                        colo_map[ip_port] = colo
                    verify_result[ip_port] = {"status": parts[4].strip() if len(parts) > 4 else "-",
                                               "conf": parts[5].strip() if len(parts) > 5 else "-"}

        print(f"\n  → 共 {len(verified_ips)} 个已验证 IP ({format_duration(time.time()-t1)})")
        print()
        try:
            progress_state.verified(len(verified_ips))
            progress_state.log(f"验证完成, 共 {len(verified_ips)} 个可用 IP (接入地区 {len(colo_map)} 个)")
        except Exception:
            pass
        except Exception:
            pass

        if not verified_ips:
            print("  ⚠ 没有验证通过的 IP")
            try:
                progress_state.done(report_path=None)
            except Exception:
                pass
            return

        # === 4/6 enrich ===
        print(f"[4/6 enrich] {'='*40}")
        t2 = time.time()
        bar_width = 24
        last_len = 0
        total_enrich = len(verified_ips)
        try:
            progress_state.stage("enrich")
            progress_state.log(f"开始补充元数据 (ASN/地区/组织), 共 {total_enrich} 个 IP")
        except Exception:
            pass
        except Exception:
            pass

        def _enrich_progress(done: int, total: int):
            nonlocal last_len
            pct = done / total if total else 1
            # 节流：本地 GeoLite2 查询毫秒级完成，每 10% 才刷一次，避免一闪而过看不到
            # 首次(1)、每 10% 边界、最后一次(100%) 必刷
            if not (done == 1 or done == total or int(pct * 10) != int((done - 1) / total * 10)):
                return
            filled = int(bar_width * pct)
            bar = "█" * filled + " " * (bar_width - filled)
            sys.stdout.write("\r" + " " * last_len + "\r")
            line = f"  补充元数据: {done}/{total} ({pct*100:.0f}%) |{bar}|"
            sys.stdout.write(line)
            sys.stdout.flush()
            last_len = len(line)
            try:
                progress_state.enrich(done, total)
            except Exception:
                pass

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
        # 标题随模式变化：-1 跳过 / None 只测延迟 / 0 延迟+速度
        _stage5_title = ("skipped" if speed_top == -1
                         else ("latency" if speed_top is None else "speedtest"))
        print(f"[5/6 {_stage5_title}] {'='*40}")
        t3 = time.time()
        try:
            progress_state.stage("speed")
        except Exception:
            pass

        # 只测非 CF 官方 IP
        to_test = [r for r in enriched if not r.get("is_cf_official")]

        # 去重：同一 ip:port 只测一次（在进入测速循环前完成，保证结果天然唯一）
        _seen = set()
        dedup_test = []
        for r in to_test:
            k = r.get("ip_port", "")
            if not k or k in _seen:
                continue
            _seen.add(k)
            dedup_test.append(r)
        to_test = dedup_test
        try:
            if speed_top == -1:
                progress_state.log("跳过测速阶段（用户选择不测延迟与速度）")
            elif speed_top is None:
                progress_state.log(f"开始测延迟, 共 {len(to_test)} 个 IP")
            else:
                progress_state.log(f"开始测速, 共 {len(to_test)} 个 IP (单线程真实满速)")
        except Exception:
            pass

        latency_only = False
        skip_stage5 = False
        if speed_top == -1:
            skip_stage5 = True   # 用户既不测延迟也不测速度，整个阶段跳过
        elif speed_top is None:
            latency_only = True  # 用户选择不测速，只测延迟
        elif speed_top > 0:
            to_test = to_test[:speed_top]

        speed_results = []
        total = 0 if skip_stage5 else len(to_test)
        if skip_stage5:
            print("  → 已跳过测速阶段（用户选择不测延迟与速度）")
            try:
                progress_state.speed(0, 0)
                progress_state.log("跳过测速阶段（用户选择）")
            except Exception:
                pass
            # 跳过时补齐空结果，保证下游合并时 latency/速度列统一为 "-"
            speed_results = [{"ip_port": r.get("ip_port", ""), "latency_ms": "-",
                              "download_mbps": 0, "error": None} for r in to_test]
        elif total == 0:
            print("  → 无需要测速的 IP" if not latency_only else "  → 无需要测延迟的 IP")
        else:
            bar_width = 24
            last_len = 0
            # 文案随模式变化：只测延迟时不写"测速"，避免误导
            stage_word = "测延迟" if latency_only else "测速"
            for i, row in enumerate(to_test, 1):
                ip_port = row["ip_port"]
                ip, port_str = ip_port.rsplit(":", 1)
                port = int(port_str)

                sr = speedtest_ip(ip, port, timeout=5.0, proxy=self.verify_proxy, latency_only=latency_only)
                speed_results.append(sr)

                pct = i / total
                filled = int(bar_width * pct)
                bar = "█" * filled + " " * (bar_width - filled)

                sys.stdout.write("\r" + " " * last_len + "\r")
                line = f"  {stage_word}: {i}/{total} ({pct*100:.0f}%) |{bar}|"
                sys.stdout.write(line)
                sys.stdout.flush()
                last_len = len(line)
                try:
                    # 计算当前平均测速速率
                    done_mbps = [r.get("download_mbps", 0) for r in speed_results if r.get("download_mbps", 0) > 0]
                    avg_mbps = sum(done_mbps) / len(done_mbps) if done_mbps else 0.0
                    progress_state.speed(i, total, avg_mbps)
                    # 每 10 个 IP 写一条实时日志（测速一个 IP 约几秒，10 个一条不刷屏）
                    if i % 10 == 0 or i == total:
                        _avg_disp = f"{avg_mbps:.1f} Mbps" if avg_mbps > 0 else "-"
                        progress_state.log(f"{stage_word} {i}/{total} ({pct*100:.0f}%) 平均 {_avg_disp}")
                except Exception:
                    pass

            sys.stdout.write("\n")
            sys.stdout.flush()

        if skip_stage5:
            print(f"  → 阶段跳过 ({format_duration(time.time()-t3)})")
        else:
            print(f"  → {'测延迟' if latency_only else '测速'}完成 ({format_duration(time.time()-t3)})")
        print()
        try:
            if skip_stage5:
                progress_state.log("测速阶段已跳过")
            elif latency_only:
                _ok = sum(1 for r in speed_results if r.get("latency_ms") not in (None, "-", ""))
                progress_state.log(f"测延迟完成, {_ok}/{len(speed_results)} 个有延迟")
            else:
                _fast = sum(1 for r in speed_results if (r.get("download_mbps") or 0) > 0)
                progress_state.log(f"测速完成, {_fast}/{len(speed_results)} 个有速度")
        except Exception:
            pass

        # === 6/6 合并数据 + 输出报告 ===
        print(f"[6/6 output] {'='*40}")
        t4 = time.time()
        # S6 分 4 步上报真实进度：合并数据 / 生成报告 / 写盘完成 / 收尾
        try:
            progress_state.stage("output")
            progress_state.output(status="running", done=0, total=4)
            progress_state.log("开始合并各阶段数据")
        except Exception:
            pass

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
            vr = verify_result.get(ip_port, {})
            merged.append({
                "ip_port": ip_port,
                "asn": row["asn"],
                "country": row["country"],
                "country_code": row.get("country_code", "-"),
                "region_name": row.get("region_name", "-"),
                "city": row.get("city", "-"),
                "continent": row.get("continent", "-"),
                "country_cn": row.get("country_cn", "-"),
                "flag": row.get("flag", "-"),
                "org": row["org"],
                "is_cf_official": row["is_cf_official"],
                "ip_type": ip_type,
                "colo": colo_map.get(ip_port, "-"),
                "latency_ms": sp.get("latency_ms", "-"),
                "download_mbps": sp.get("download_mbps", 0),
                "tls": sp.get("tls", "-") if sp.get("tls") else "-",
                "alpn": sp.get("alpn", "-") if sp.get("alpn") else "-",
                "verify_status": vr.get("status", "-"),
                "verify_conf": vr.get("conf", "-"),
                "verify_reason": row.get("verify_reason", "-"),
                "confidence": row.get("confidence", "-"),
            })

        try:
            progress_state.output(status="running", done=1, total=4)
            progress_state.log(f"数据合并完成, 共 {len(merged)} 条")
        except Exception:
            pass

        from asnip import _get_public_ip
        public_ip = _get_public_ip() or "-"

        # 生成带时间戳的规范文件名（标识 = ASN 或 CIDR 主段）
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_basename = f"output_{target_label}_{ts}"

        try:
            progress_state.output(status="running", done=2, total=4)
            progress_state.log("生成报告 CSV/JSON")
        except Exception:
            pass

        stats = generate_report(
            merged,
            output_dir=self.workdir,
            top_n=top_n,
            keep_cf_official=False,
            json_output=json_output,
            public_ip=public_ip,
            colo_map=colo_map,
            basename=report_basename,
        )

        try:
            progress_state.output(status="running", done=3, total=4,
                                  report_path=stats.get("csv_path"))
            progress_state.log(f"报告已写盘: {os.path.basename(stats.get('csv_path') or '')}")
        except Exception:
            pass

        total_elapsed = time.time() - start_total
        try:
            progress_state.done(report_path=stats.get("csv_path"))
            progress_state.log(f"报告已生成: {stats.get('csv_path')}")
        except Exception:
            pass
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
