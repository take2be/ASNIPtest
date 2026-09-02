#!/usr/bin/env python3
"""attach_guard — 仅在 screen 会话被 attach 时开放 HTTP 服务。

背景（安全）
------------
面板（8082）与结果下载（8081）都监听 0.0.0.0。若长期常驻，任何人扫到端口
就能看扫描数据、甚至下载整个安装目录。但 VPS 是远程的，绑 127.0.0.1 等于
拿不到结果，所以不能一关了之。

折中方案：**服务生命周期跟随 attach 状态**
    detach → 端口彻底关闭（外部扫端口一无所获）
    attach → 拉起服务并打印带一次性 token 的地址
暴露窗口 = 用户真正盯着屏幕的那几分钟。

attach 检测
-----------
实测（GNU screen 4.09）：会话内 `screen -ls | grep -F "$STY"` 的输出带
`(Attached)` / `(Detached)` 标记，状态切换无延迟，可靠可用。
注意不能用 `sys.stdout.isatty()` 判断 —— detach 不会关闭进程的 pty，
isatty() 始终为 True。

token
-----
每次开放生成新的一次性 token（32 位 hex），只 print 到已 attach 的终端，
不写日志文件、不进进程命令行（避免 /tmp 日志 644 与 ps aux 泄漏）。
"""
import os
import secrets
import subprocess
import sys
import threading
import time


POLL_INTERVAL = 2.0     # attach 状态轮询间隔（秒）
_GRACE_AFTER_DONE = 0   # 扫描结束后的宽限期（秒）；0 = 严格跟随 attach


def _sty() -> str:
    """当前 screen 会话标识（形如 '463.asnip-36002'）。非 screen 环境返回空。"""
    return os.environ.get("STY", "") or ""


def in_screen() -> bool:
    return bool(_sty())


def is_attached(default: bool = True) -> bool:
    """当前 screen 会话是否处于 attached 状态。

    非 screen 环境（直接前台跑）返回 default=True —— 用户就在终端前面，
    等价于 attached。
    """
    sty = _sty()
    if not sty:
        return default
    try:
        out = subprocess.run(
            ["screen", "-ls"], capture_output=True, text=True, timeout=5
        ).stdout or ""
    except Exception:
        # screen 命令不可用时不要误判成 detached（否则服务永远起不来）
        return default
    for line in out.splitlines():
        if sty in line:
            if "(Attached)" in line:
                return True
            if "(Detached)" in line:
                return False
            # 少见状态（Multi/Dead）按未 attach 处理，宁可关掉端口
            return False
    # 会话不在列表里（刚退出/被 wipe）→ 视为未 attach
    return False


def new_token() -> str:
    """生成一次性访问令牌（128 bit）。"""
    return secrets.token_hex(16)


class AttachGatedServer:
    """按 attach 状态启停一个 HTTP 服务。

    factory(token) 必须返回一个已绑定端口、未 serve 的 server 对象，
    要求具备 serve_forever() / shutdown() / server_close()。
    """

    def __init__(self, name: str, port: int, factory, on_open=None, on_close=None):
        self.name = name
        self.port = port
        self.factory = factory
        self.on_open = on_open
        self.on_close = on_close
        self._server = None
        self._thread = None
        self._token = ""
        self._lock = threading.Lock()

    # ---- 生命周期 ----
    def open(self):
        with self._lock:
            if self._server is not None:
                return True
            self._token = new_token()
            try:
                self._server = self.factory(self.port, self._token)
            except OSError as e:
                print(f"  ⚠ {self.name} 启动失败（端口 {self.port} 被占用？）: {e}")
                self._server = None
                self._token = ""
                return False
            except Exception as e:
                print(f"  ⚠ {self.name} 启动失败: {e}")
                self._server = None
                self._token = ""
                return False
            self._thread = threading.Thread(
                target=self._server.serve_forever, kwargs={"poll_interval": 0.5},
                daemon=True,
            )
            self._thread.start()
        if self.on_open:
            try:
                self.on_open(self._token)
            except Exception:
                pass
        return True

    def close(self, quiet: bool = False):
        with self._lock:
            srv, self._server = self._server, None
            th, self._thread = self._thread, None
            self._token = ""
        if srv is None:
            return
        try:
            srv.shutdown()
        except Exception:
            pass
        try:
            srv.server_close()
        except Exception:
            pass
        if th is not None:
            try:
                th.join(timeout=3)
            except Exception:
                pass
        if self.on_close and not quiet:
            try:
                self.on_close()
            except Exception:
                pass

    @property
    def is_open(self) -> bool:
        return self._server is not None

    @property
    def token(self) -> str:
        return self._token


class AttachGuard:
    """轮询 attach 状态，统一驱动多个 AttachGatedServer 的启停。

    用法：
        guard = AttachGuard([panel, download], on_all_open=cb)
        guard.start()                 # 后台线程持续跟随 attach 状态
        guard.force_open()            # 已 attach 时立刻开放，不等轮询
        guard.wait_forever()          # 阻塞直到 Ctrl+C
        guard.stop()                  # 收尾，关闭全部服务
    """

    def __init__(self, servers, poll: float = POLL_INTERVAL, on_all_open=None):
        self.servers = list(servers)
        self.poll = poll
        self.on_all_open = on_all_open
        self._stop = threading.Event()
        self._thread = None
        self._attached = None   # 上一次已知状态，None = 尚未判定
        self._lock = threading.Lock()

    def _open_all(self):
        opened_any = False
        for s in self.servers:
            if not s.is_open:
                if s.open():
                    opened_any = True
        if opened_any and self.on_all_open:
            try:
                self.on_all_open()
            except Exception:
                pass

    def _close_all(self):
        for s in self.servers:
            if s.is_open:
                s.close()

    def force_open(self):
        """立刻开放（用于进入等待时已处于 attached 的情况）。"""
        with self._lock:
            self._attached = True
            self._open_all()

    def _loop(self):
        while not self._stop.is_set():
            try:
                att = is_attached()
                with self._lock:
                    if att != self._attached:
                        self._attached = att
                        if att:
                            print()
                            print("  🔓 检测到 attach —— 开放 HTTP 服务")
                            self._flush()
                            self._open_all()
                        else:
                            # detach 后终端看不到输出，这里只进 screen 缓冲
                            print("  🔒 检测到 detach —— 关闭 HTTP 服务（端口不再监听）")
                            self._flush()
                            self._close_all()
            except Exception:
                pass
            self._stop.wait(self.poll)

    @staticmethod
    def _flush():
        # stdout 重定向到文件时是块缓冲，不 flush 会让状态提示迟迟不出现
        try:
            sys.stdout.flush()
        except Exception:
            pass

    def start(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def wait_forever(self):
        """阻塞等待，直到 Ctrl+C 或进程被终止。"""
        try:
            while not self._stop.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            print()
            print("  收到 Ctrl+C，正在停止服务...")

    def stop(self):
        self._stop.set()
        for s in self.servers:
            s.close(quiet=True)
        if self._thread is not None:
            try:
                self._thread.join(timeout=3)
            except Exception:
                pass
            self._thread = None
