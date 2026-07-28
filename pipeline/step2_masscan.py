"""② masscan 全端口发现 + 验证流水线 + Block Plan 调度

按设计文档实现：
- Plan 生成 → scan_plan.json
- 水位控制（背压）
- 原子写产物
- IP:Port 级 Resume
"""

import os
import sys
import time
import json
import hashlib
import subprocess
import threading
import queue
from pathlib import Path

from .utils import log, CACHE_DIR, atomic_write, sha256_text, clear_proxy_env

# ── 默认参数 ──────────────────────────────────────────────────────────
DEFAULT_PORTS = "443,2053,2083,2087,2096,8443"
DEFAULT_BLOCK_SIZE = 500
HIGH_WATER = 10000
LOW_WATER = 5000
SCAN_SCHEMA = 1


def _plan_blocks(cidrs: list[str], block_size: int = DEFAULT_BLOCK_SIZE) -> list[dict]:
    """确定性全量规划：按 CIDR 列表切块

    Args:
        cidrs: CIDR 字符串列表
        block_size: 每块 CIDR 条数

    Returns:
        [{index, cidr_range:{start_idx,end_idx}, block_input_hash, cidrs_file}, ...]
    """
    blocks = []
    total = len(cidrs)
    for i in range(0, total, block_size):
        end = min(i + block_size, total)
        chunk = cidrs[i:end]
        blocks.append({
            "index": len(blocks) + 1,
            "cidr_range": {"start_idx": i, "end_idx": end},
            "block_input_hash": hashlib.sha256(
                "\n".join(chunk).encode()
            ).hexdigest(),
            "cidrs_file": f"block_{len(blocks) + 1:03d}_cidrs.txt",
        })
    return blocks


def _normalize_ports(ports: str) -> str:
    """端口规范：拆分、去重、排序、合并连续区间 → canonical string"""
    parts = ports.replace(" ", "").split(",")
    nums = set()
    for p in parts:
        if "-" in p:
            lo, hi = p.split("-", 1)
            nums.update(range(int(lo), int(hi) + 1))
        else:
            nums.add(int(p))
    return ",".join(str(n) for n in sorted(nums))


def _ports_hash(ports_str: str) -> str:
    """端口集的 SHA256"""
    return sha256_text(ports_str)


class MasscanScheduler:
    """masscan 调度器 — 单生产者 + 多消费者

    属性:
        asn: AS 号
        cidrs: 完整 CIDR 列表
        ports: 端口集字符串
        work_dir: 工作目录（存 plan + block 文件）
        verify_workers: verify 线程数
        proxy: SOCKS5 代理地址（可选）
        _queue: 待验证 IP:Port 队列
        _completed: 已完成 IP:Port set
        _stop: 停止信号
    """

    def __init__(
        self,
        cidrs: list[str],
        ports: str = DEFAULT_PORTS,
        work_dir: str | Path = None,
        asn: str = "",
        block_size: int = DEFAULT_BLOCK_SIZE,
        verify_workers: int = 32,
        proxy: str = None,
    ):
        self.cidrs = cidrs
        self.ports = _normalize_ports(ports)
        self.work_dir = Path(work_dir or CACHE_DIR)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.asn = asn
        self.block_size = block_size
        self.verify_workers = verify_workers
        self.proxy = proxy

        self._queue = queue.Queue(maxsize=HIGH_WATER + 5000)
        self._completed: set[str] = set()
        self._stop = False
        self._scan_rate = 2000  # default masscan rate
        self._lock = threading.Lock()

        # 自动识别 WSL 调整 rate
        self._is_wsl = self._check_wsl()
        if self._is_wsl:
            self._scan_rate = 2000

    # ── 工具 ──────────────────────────────────────────────────────

    @staticmethod
    def _check_wsl() -> bool:
        try:
            with open("/proc/version", "r") as f:
                return "microsoft" in f.read().lower()
        except Exception:
            return False

    @staticmethod
    def _get_cpu_cores() -> int:
        try:
            result = subprocess.run(
                ["nproc"], capture_output=True, text=True, timeout=5
            )
            return int(result.stdout.strip())
        except Exception:
            return 4

    def _can_sudo(self) -> bool:
        """检查是否有密码 sudo 权限（masscan 需要 root）"""
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"], capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    # ── Plan 生成 ─────────────────────────────────────────────────

    def generate_plan(self) -> dict:
        """生成 scan_plan.json，写原子文件"""
        blocks = _plan_blocks(self.cidrs, self.block_size)
        ports_hash = _ports_hash(self.ports)

        plan = {
            "resume_identity": {
                "asn": self.asn,
                "ports_hash": ports_hash,
                "verify_method": "hybrid",
                "scan_schema": SCAN_SCHEMA,
            },
            "runtime_info": {
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "total_blocks": len(blocks),
                "total_cidrs": len(self.cidrs),
                "ports": self.ports,
            },
            "blocks": blocks,
        }

        # 写 Plan
        plan_path = self.work_dir / "scan_plan.json"
        atomic_write(str(plan_path), json.dumps(plan, indent=2))
        log.info(f"  📋 Plan 已写入: {plan_path} ({len(blocks)} blocks)")

        return plan

    # ── 材料化 Block 文件 ─────────────────────────────────────────

    def materialize_blocks(self, plan: dict) -> None:
        """生成各 block_NNN_cidrs.txt 文件"""
        for blk in plan["blocks"]:
            start = blk["cidr_range"]["start_idx"]
            end = blk["cidr_range"]["end_idx"]
            chunk = self.cidrs[start:end]
            cidrs_file = self.work_dir / blk["cidrs_file"]
            with open(cidrs_file, "w") as f:
                f.write("\n".join(chunk) + "\n")
            log.info(f"  📄 {blk['cidrs_file']}: {len(chunk)} CIDRs")

    # ── 扫描块 ────────────────────────────────────────────────────

    def _scan_block(self, blk: dict) -> str | None:
        """执行 masscan 扫描一个块，返回 JSON 文件路径，失败返回 None"""
        cidrs_file = str(self.work_dir / blk["cidrs_file"])
        out_file = str(self.work_dir / f"block_{blk['index']:03d}.json")
        tmp_file = out_file + ".tmp"

        cmd = [
            "sudo", "masscan",
            "-iL", cidrs_file,
            "-p", self.ports,
            "--rate", str(self._scan_rate),
            "-oJ", tmp_file,
            "--wait", "5",
            "--max-retries", "1",
        ]

        # 非 root 自动加 sudo
        if not self._can_sudo():
            cmd = cmd[1:]  # 去掉 sudo

        log.info(f"  🔍 Block {blk['index']:03d}: masscan {blk['cidrs_file']}...")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            if result.returncode == 0 and os.path.getsize(tmp_file) > 10:
                os.replace(tmp_file, out_file)
                log.info(f"  ✅ Block {blk['index']:03d}: scan 完成 -> {os.path.basename(out_file)}")
                return out_file
            else:
                log.warning(f"  ⚠️ Block {blk['index']:03d}: masscan 退出码={result.returncode}")
                # 清理残留 .tmp
                if os.path.exists(tmp_file):
                    os.unlink(tmp_file)
                return None
        except subprocess.TimeoutExpired:
            log.warning(f"  ⚠️ Block {blk['index']:03d}: masscan 超时")
            if os.path.exists(tmp_file):
                os.unlink(tmp_file)
            return None
        except Exception as e:
            log.warning(f"  ⚠️ Block {blk['index']:03d}: masscan 异常: {e}")
            if os.path.exists(tmp_file):
                os.unlink(tmp_file)
            return None

    # ── Verify 消费者 ─────────────────────────────────────────────

    def _verify_worker(self, verify_func):
        """消费者线程：从队列取 IP:Port 调 verify 函数"""
        while not self._stop:
            try:
                item = self._queue.get(timeout=1)
            except queue.Empty:
                continue

            ip_port = item  # "ip:port"
            ip, port_str = ip_port.rsplit(":", 1)
            port = int(port_str)

            try:
                result = verify_func(ip, port)
                with self._lock:
                    self._completed.add(ip_port)
            except Exception as e:
                with self._lock:
                    self._completed.add(ip_port)
            finally:
                self._queue.task_done()

    # ── Resume 恢复 ───────────────────────────────────────────────

    def load_completed(self, plan: dict) -> set[str]:
        """从已有产物读已完成 IP:Port"""
        completed = set()
        for blk in plan["blocks"]:
            idx = blk["index"]
            cf_file = self.work_dir / f"block_{idx:03d}.cf.txt"
            cf_tmp = self.work_dir / f"block_{idx:03d}.cf.tmp"
            json_file = self.work_dir / f"block_{idx:03d}.json"

            # 有 .cf.txt → 块已完全完成
            if cf_file.exists():
                for line in cf_file.read_text().strip().splitlines():
                    line = line.strip()
                    if line:
                        parts = line.split()
                        if len(parts) >= 1:
                            completed.add(parts[0])
                log.info(f"  📂 Block {idx:03d}: .cf.txt 已存在 ({len(cf_file.read_text().splitlines())} IPs)")
                continue

            # 仅有 .cf.tmp → 部分完成
            if cf_tmp.exists():
                for line in cf_tmp.read_text().strip().splitlines():
                    line = line.strip()
                    if line:
                        parts = line.split()
                        if len(parts) >= 1:
                            completed.add(parts[0])
                log.info(f"  📂 Block {idx:03d}: 恢复 .cf.tmp (partial)")
                continue

            # 仅有 .json → 已扫未验
            if json_file.exists():
                log.info(f"  📂 Block {idx:03d}: .json 已存在，待 verify")

        return completed

    # ── 主循环 ────────────────────────────────────────────────────

    def run(self, verify_func) -> dict:
        """执行全流程扫描

        Args:
            verify_func: (ip, port) -> bool | None，CF 判定函数

        Returns:
            {
                "plan": scan_plan,
                "blocks_scanned": int,
                "total_targets": int,
                "completed": int,
                "elapsed": float,
            }
        """
        start = time.monotonic()

        # 1. 生成/加载 Plan
        plan_path = self.work_dir / "scan_plan.json"
        if plan_path.exists():
            plan = json.loads(plan_path.read_text())
            log.info(f"  📋 加载已有 Plan ({len(plan['blocks'])} blocks)")
        else:
            plan = self.generate_plan()
            self.materialize_blocks(plan)

        # 2. 加载已完成的 IP:Port
        self._completed = self.load_completed(plan)

        # 3. 启动 verify 消费者
        verify_threads = []
        for _ in range(self.verify_workers):
            t = threading.Thread(target=self._verify_worker, args=(verify_func,), daemon=True)
            t.start()
            verify_threads.append(t)

        # 4. 主循环：逐个扫描块
        blocks_scanned = 0
        total_targets = 0

        try:
            for blk in plan["blocks"]:
                idx = blk["index"]
                json_file = self.work_dir / f"block_{idx:03d}.json"
                cf_file = self.work_dir / f"block_{idx:03d}.cf.txt"

                # 已完全完成 → 跳过
                if cf_file.exists():
                    log.info(f"  ⏭️ Block {idx:03d}: 跳过（已有 .cf.txt）")
                    blocks_scanned += 1
                    continue

                # 水位控制
                while self._queue.qsize() > HIGH_WATER and not self._stop:
                    log.info(f"  💧 水位 {self._queue.qsize()}/{HIGH_WATER}，暂停起新块...")
                    time.sleep(3)

                if self._stop:
                    break

                # 扫描块
                if not json_file.exists():
                    result = self._scan_block(blk)
                    if result is None:
                        log.warning(f"  ⚠️ Block {idx:03d}: 扫描失败，跳过")
                        continue

                # 解析 JSON → 入队 IP:Port
                try:
                    with open(json_file) as f:
                        content = f.read().strip()
                except Exception as e:
                    log.warning(f"  ⚠️ Block {idx:03d}: 读取 JSON 失败: {e}")
                    continue

                if not content:
                    # 空块 → 写空 cf 文件防阻塞
                    self._write_empty_cf(idx)
                    continue

                lines = content.strip().splitlines()
                targets = 0
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        ip = entry.get("ip", "")
                        port = entry.get("ports", "")
                        if not ip or not port:
                            continue
                        ip_port = f"{ip}:{port}"
                        if ip_port in self._completed:
                            continue
                        self._queue.put(ip_port)
                        targets += 1
                    except (json.JSONDecodeError, ValueError):
                        continue

                total_targets += targets
                log.info(f"  📥 Block {idx:03d}: 入队 {targets} 个新目标 (累计 {total_targets})")
                blocks_scanned += 1

                # 等待队列排空（但不等到空，只等水位降）
                while self._queue.qsize() > LOW_WATER and not self._stop:
                    time.sleep(2)

        except KeyboardInterrupt:
            log.info("  🛑 用户中断")
            self._stop = True

        # 等待所有 verify 完成
        log.info("  ⏳ 等待 verify 消费者完成...")
        self._queue.join()
        self._stop = True

        elapsed = time.monotonic() - start

        return {
            "plan": plan,
            "blocks_scanned": blocks_scanned,
            "total_targets": total_targets,
            "completed": len(self._completed),
            "elapsed": elapsed,
        }

    def _write_empty_cf(self, idx: int):
        """空块写空 .cf.txt 防阻塞"""
        path = self.work_dir / f"block_{idx:03d}.cf.txt"
        if not path.exists():
            atomic_write(str(path), "")
            log.info(f"  📄 Block {idx:03d}: 空块，写空 .cf.txt")


# ── 独立测试 ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法: python -m pipeline.step2_masscan <asn> [cidr1 cidr2 ...]")
        sys.exit(1)

    # 从命令行取测试 CIDR（典型场景：传 ASN 或直接传 CIDR）
    test_cidrs = ["1.1.1.0/24", "8.8.8.0/24"]  # 默认测试
    if len(sys.argv) > 1:
        # 如果第一个参数是纯数字，当 ASN 处理
        if sys.argv[1].isdigit():
            from .step1_cidr import fetch_cidrs
            test_cidrs = fetch_cidrs(sys.argv[1], force=False)
        else:
            test_cidrs = sys.argv[1:]

    if not test_cidrs:
        print("无 CIDR 输入，退出")
        sys.exit(1)

    print(f"\n测试 CIDR 数: {len(test_cidrs)}")
    scheduler = MasscanScheduler(
        cidrs=test_cidrs,
        asn=sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].isdigit() else "test",
        work_dir=CACHE_DIR / "test_scan",
        block_size=5,  # 小块方便测试
    )

    # 用简单桩函数测试 (不会实际验证，只走框架)
    def mock_verify(ip: str, port: int) -> bool:
        return True

    result = scheduler.run(mock_verify)
    print(f"\n结果: blocks_scanned={result['blocks_scanned']}, "
          f"total_targets={result['total_targets']}, "
          f"elapsed={result['elapsed']:.1f}s")
