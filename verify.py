#!/usr/bin/env python3
# verify.py —— ASNIPtest-optimized ③ 验证框架（严格按设计文档 ③ 实现）
# 本模块是 ③ 的 reference 实现：VerifyResult + VerifyPlugin + hybrid 状态机。
# 探针/主程序一律 import 本模块，禁止另写 ad-hoc ssl 代码。
import ssl, socket, time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List

try:
    from cryptography import x509
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

# ───────────────────────── ③.2 框架类型 ─────────────────────────
class Reason(str, Enum):
    SUBJECT_MATCH     = "subject_match"      # TLS leaf subject O 含 cloudflare（主判据，设计定义）
    ISSUER_MATCH      = "issuer_match"       # TLS issuer O 含 cloudflare（辅）
    HTTP_CF_RAY       = "http_cf_ray"         # HTTP 响应含 CF-RAY 头
    SERVER_CLOUDFLARE = "server_cloudflare"  # HTTP Server 头 == cloudflare
    TIMEOUT           = "timeout"
    TLS_ERROR         = "tls_error"
    NO_CERTIFICATE    = "no_certificate"
    CONNECTION_REFUSED= "connection_refused"
    CONN_ERROR        = "conn_error"
    # 以下为本实现实测暴露的设计缺口补充信号（非原枚举，见 probe 报告）：
    TLS_NO_MATCH      = "tls_no_match"       # 握手成功/证书存在，但 subject O 与 issuer O 均不含 cloudflare
                                             #   ← 设计③.3 只定义 subject/issuer O 为信号，未覆盖此“有证无证不匹配”态
    CN_MATCH          = "cn_match"           # 实测补充：subject CN 含 cloudflare（设计未列，待补进枚举）

class Confidence(str, Enum):
    HIGH = "high"; MEDIUM = "medium"; LOW = "low"; EXTERNAL = "external"

class Result(str, Enum):
    PASS = "PASS"; FAIL = "FAIL"; UNKNOWN = "UNKNOWN"

@dataclass
class VerifyResult:
    result: Result
    method: str
    reason: Reason
    confidence: Confidence
    extras: Dict = field(default_factory=dict)

@dataclass
class VerifyConfig:
    sni: Optional[str] = None          # ③.5：None=不发SNI(取服务端默认证书)
    conn_timeout: float = 2.0          # ③.6
    tls_timeout: float = 5.0
    http_timeout: float = 5.0
    use_proxy: bool = False            # ③.11：是否走 socks5 出口取证
    proxy_addr: tuple = ("127.0.0.1", 10808)

# ───────────────────────── 出口（③.11） ─────────────────────────
def _socks5_connect(target, proxy, timeout):
    s = socket.create_connection(proxy, timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    s.recv(2)
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(target[0]) + target[1].to_bytes(2, "big"))
    rep = s.recv(10)
    if rep[1] != 0:
        s.close(); raise ConnectionError(f"socks5 code {rep[1]}")
    return s

def _connect(ip, port, cfg):
    if cfg.use_proxy:
        return _socks5_connect((ip, port), cfg.proxy_addr, cfg.conn_timeout)
    return socket.create_connection((ip, port), timeout=cfg.conn_timeout)

# ───────────────────────── 证书解析 ─────────────────────────
def _parse_cert(der):
    """返回 (subj_o, iss_o, cn, san_list)，解析失败返回空串/空列表。"""
    if not der or not _HAS_CRYPTO:
        return "", "", "", []
    try:
        c = x509.load_der_x509_certificate(der)
        def o_of(n):
            try:
                for rdn in n:
                    for av in rdn:
                        if av[0] == "organizationName":
                            return av[1]
            except Exception:
                pass
            return ""
        subj_o = o_of(c.subject)
        iss_o  = o_of(c.issuer)
        cn = ""
        try:
            cn = c.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        except Exception:
            pass
        san = []
        try:
            san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        return subj_o, iss_o, cn, san
    except Exception:
        return "", "", "", []

# ───────────────────────── tls 插件（③.3） ─────────────────────────
def tls_decide(ip, port, cfg) -> (VerifyResult, Optional[socket.socket]):
    """返回 (result, established_socket_or_None)。
    socket 仅在证书可解析、需进一步 http 补充时回传（强约束B：复用同一socket）。"""
    try:
        raw = _connect(ip, port, cfg)
    except socket.timeout:
        return VerifyResult(Result.UNKNOWN, "tls", Reason.TIMEOUT, Confidence.LOW, {}), None
    except ConnectionRefusedError:
        return VerifyResult(Result.FAIL, "tls", Reason.CONNECTION_REFUSED, Confidence.HIGH, {}), None
    except OSError as e:
        return VerifyResult(Result.UNKNOWN, "tls", Reason.CONN_ERROR, Confidence.LOW, {"err": str(e)[:50]}), None

    ssock = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(raw, server_hostname=cfg.sni)
        ssock.do_handshake()   # 显式握手（修复 getpeercert()=None 的坑）
        extras = {"tls_version": ssock.version(),
                  "cipher": (ssock.cipher() or [None])[0],
                  "alpn": ssock.selected_alpn_protocol()}
        der = ssock.getpeercert(binary_form=True)
    except ssl.SSLError as e:
        return VerifyResult(Result.UNKNOWN, "tls", Reason.TLS_ERROR, Confidence.LOW, {"err": str(e)[:50]}), None
    except (socket.timeout, ConnectionResetError, ConnectionAbortedError, OSError) as e:
        return VerifyResult(Result.UNKNOWN, "tls", Reason.CONN_ERROR, Confidence.LOW, {"err": str(e)[:50]}), None


    if not der:
        return VerifyResult(Result.UNKNOWN, "tls", Reason.NO_CERTIFICATE, Confidence.LOW, extras), None

    subj_o, iss_o, cn, san = _parse_cert(der)
    extras.update({"subj_o": subj_o, "iss_o": iss_o, "cn": cn, "san": san[:5]})

    # 设计③.3 主/辅信号：subject O / issuer O 含 cloudflare
    if "cloudflare" in subj_o.lower():
        return VerifyResult(Result.PASS, "tls", Reason.SUBJECT_MATCH, Confidence.HIGH, extras), ssock
    if "cloudflare" in iss_o.lower():
        return VerifyResult(Result.PASS, "tls", Reason.ISSUER_MATCH, Confidence.HIGH, extras), ssock
    # 设计未覆盖态：有证但 O 字段都不含 cloudflare → UNKNOWN，交由 http 补充
    # 同时把实测可见的 CN/SAN 信号作为 extras 记录（供探针诊断，不参与判定）
    if "cloudflare" in cn.lower() or any("cloudflare" in s.lower() for s in san):
        extras["_diag_cf_in_cn_san"] = True
        return VerifyResult(Result.UNKNOWN, "tls", Reason.TLS_NO_MATCH, Confidence.LOW, extras), ssock
    return VerifyResult(Result.UNKNOWN, "tls", Reason.TLS_NO_MATCH, Confidence.LOW, extras), ssock

# ───────────────────────── http 插件（③.3，复用已建 socket） ─────────────────────────
def http_decide_on_socket(ssock, cfg) -> VerifyResult:
    """强约束(B)：必须在 tls 已建 socket 上发请求，禁止重握。"""
    try:
        ssock.settimeout(cfg.http_timeout)
        req = (f"GET / HTTP/1.1\r\nHost: {cfg.sni or 'localhost'}\r\n"
               f"User-Agent: ASNIPtest/0.1\r\nConnection: close\r\n\r\n").encode()
        ssock.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            d = ssock.recv(4096)
            if not d: break
            buf += d
        head = buf.split(b"\r\n\r\n")[0].decode(errors="replace")
        hdrs = {k.strip().lower(): v.strip() for k, v in
                (line.split(":", 1) for line in head.split("\r\n")[1:] if ":" in line)}
        if "cf-ray" in hdrs:
            return VerifyResult(Result.PASS, "http", Reason.HTTP_CF_RAY, Confidence.MEDIUM, {"head": head[:120]})
        sv = hdrs.get("server", "")
        if "cloudflare" in sv.lower():
            return VerifyResult(Result.PASS, "http", Reason.SERVER_CLOUDFLARE, Confidence.MEDIUM, {"server": sv})
        return VerifyResult(Result.UNKNOWN, "http", Reason.TLS_NO_MATCH, Confidence.LOW,
                            {"server": sv, "has_cf_ray": "cf-ray" in hdrs})
    except socket.timeout:
        return VerifyResult(Result.UNKNOWN, "http", Reason.TIMEOUT, Confidence.LOW, {})
    except Exception as e:
        return VerifyResult(Result.UNKNOWN, "http", Reason.CONN_ERROR, Confidence.LOW, {"err": str(e)[:50]})

# ───────────────────────── hybrid 状态机（③.3） ─────────────────────────
def hybrid_verify(ip, port, cfg) -> VerifyResult:
    res, sock = tls_decide(ip, port, cfg)
    if res.result in (Result.PASS, Result.FAIL):
        return res                       # TLS PASS/FAIL 即结束，http 永不推翻
    if sock is not None:
        try:
            http_res = http_decide_on_socket(sock, cfg)
            return http_res
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return res                            # 无 socket 可复用 → 维持 tls 的 UNKNOWN

# 插件注册表（③.4：换算法=加类+注册，主流程零改）
VERIFIERS = {"tls": tls_decide, "http": None, "hybrid": hybrid_verify}

def verify(ip, port, cfg, mode="hybrid"):
    if mode == "hybrid":
        return hybrid_verify(ip, port, cfg)
    if mode == "tls":
        r, _ = tls_decide(ip, port, cfg)
        return r
    raise ValueError(f"unsupported mode {mode}")
