#!/usr/bin/env python3
# 连通性诊断：针对 1~3 个已知真 CF IP，分别测 直连 / 真SOCKS5，dump 完整证书与异常
import ssl, socket, sys

PROXY = ("127.0.0.1", 10808)
TIMEOUT = 8

def o_of(x):
    for rdn in x:
        for av in rdn:
            if av[0] == "organizationName":
                return av[1]
    return ""

def socks5_connect(target, verbose=False):
    s = socket.create_connection(PROXY, timeout=TIMEOUT)
    s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    if verbose: print("  socks5 greeting reply:", r)
    if r[0] != 5:
        raise RuntimeError("bad greeting")
    host, port = target
    req = b"\x05\x01\x00\x01" + socket.inet_aton(host) + port.to_bytes(2, "big")
    if verbose: print("  socks5 req:", req.hex())
    s.sendall(req)
    rep = s.recv(10)
    if verbose: print("  socks5 reply:", rep.hex())
    if rep[1] != 0:
        s.close(); raise RuntimeError(f"conn fail code={rep[1]}")
    return s

def try_one(ip, port, via_proxy, sni_val=None, verbose=False):
    tag = "PROXY" if via_proxy else "DIRECT"
    print(f"\n### {tag} -> {ip}:{port}  sni={sni_val}")
    try:
        raw = socks5_connect((ip, port), verbose) if via_proxy else socket.create_connection((ip, port), timeout=TIMEOUT)
    except Exception as e:
        print("  CONNECT FAIL:", repr(e)); return
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        server = sni_val
        print(f"  wrap_socket server_hostname={server!r}")
        ssock = ctx.wrap_socket(raw, server_hostname=server)
        print("  HANDSHAKE OK, version:", ssock.version(), "cipher:", ssock.cipher()[0])
        cert = ssock.getpeercert()
        if cert:
            print("  CERT subj:", {k: v for rdn in cert.get("subject", ()) for av in rdn for k, v in [av] if k == "organizationName"})
            print("  CERT subj_O:", o_of(cert.get("subject", ())))
            print("  CERT iss_O :", o_of(cert.get("issuer", ())))
            print("  CERT SAN  :", cert.get("subjectAltName"))
        else:
            print("  NO CERT")
        ssock.close()
    except Exception as e:
        print("  TLS FAIL:", repr(e))
    finally:
        try: raw.close()
        except Exception: pass

if __name__ == "__main__":
    # 来自样本的已知真 CF 边缘 IP（ASN=13335）
    targets = [("43.160.226.219", 443), ("140.245.103.72", 443)]
    for ip, port in targets:
        try_one(ip, port, False, None, verbose=True)   # 直连 不发SNI
        try_one(ip, port, True,  None, verbose=True)   # 代理 不发SNI
        try_one(ip, port, True,  ip,   verbose=True)   # 代理 发SNI=IP
