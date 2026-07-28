#!/usr/bin/env python3
# 诊断 v2：用 ssl.get_server_certificate（专为取证书设计，最稳）验证能否拿到真 CF 证书
# 同时验证 SOCKS5 出口下能否取证书（get_server_certificate 不支持代理，故代理走手动 wrap+显式 handshake）
import ssl, socket
from cryptography import x509  # 若没装就回退到解析 getpeercert 字典

PROXY = ("127.0.0.1", 10808)
TIMEOUT = 8

def o_of(name_obj):
    try:
        for rdn in name_obj:
            for av in rdn:
                if av[0] == "organizationName":
                    return av[1]
    except Exception:
        pass
    return ""

def via_direct_get_cert(ip, port, sni=None):
    # get_server_certificate 不支持 SNI 发包目标之外的 SNI，但 server_hostname 可指定
    try:
        pem = ssl.get_server_certificate((ip, port), ssl.create_default_context(), server_hostname=sni)
        return "ok", pem
    except Exception as e:
        return "fail", repr(e)

def via_socks5_get_cert(ip, port, sni=None):
    s = socket.create_connection(PROXY, timeout=TIMEOUT)
    s.sendall(b"\x05\x01\x00")
    s.recv(2)
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + port.to_bytes(2, "big"))
    rep = s.recv(10)
    if rep[1] != 0:
        s.close(); return "fail", f"socks5 code {rep[1]}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ssock = ctx.wrap_socket(s, server_hostname=sni)
    ssock.do_handshake()
    der = ssock.getpeercert(binary_form=True)
    ssock.close()
    if not der:
        return "nocert", ""
    return "ok", der.hex()[:40] + "..."

def main():
    targets = [("43.160.226.219", 443), ("140.245.103.72", 443)]  # 样本里 AS 13335 真 CF
    for ip, port in targets:
        print(f"\n### {ip}:{port}")
        for sni in (None, ip):
            st, data = via_direct_get_cert(ip, port, sni)
            print(f"  DIRECT sni={sni} -> {st}: {data[:70] if isinstance(data,str) else data}")
            st2, data2 = via_socks5_get_cert(ip, port, sni)
            print(f"  PROXY  sni={sni} -> {st2}: {data2}")

if __name__ == "__main__":
    main()
