#!/usr/bin/env python3
# 探针 v2：修复 SOCKS5 出口（v1 误用 HTTP CONNECT 对 SOCKS5 代理，隧道失效）
# 维度：① 样本分层(组A官方13335 / 组B第三方目标) ② SNI(none vs IP) ③ 出口(direct vs socks5)
import ssl, socket, csv, random
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

SRC   = os.path.join(os.path.expanduser("~"), "AppData", "Local", "hermes", "cache", "documents", "doc_1b62c45ca5ea_Global-proxyip-443.csv")
PROXY = ("127.0.0.1", 10808)
TIMEOUT = 6

def o_of(x509_name):
    for rdn in x509_name:
        for av in rdn:
            if av[0] == "organizationName":
                return av[1]
    return ""

def socks5_connect(target):
    s = socket.create_connection(PROXY, timeout=TIMEOUT)
    s.sendall(b"\x05\x01\x00")                 # greeting: SOCKS5, no-auth
    if s.recv(2)[0] != 5: raise RuntimeError("socks5 greeting")
    host, port = target
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + port.to_bytes(2, "big"))
    rep = s.recv(10)
    if rep[1] != 0: raise RuntimeError(f"socks5 conn fail code={rep[1]}")
    return s

def probe(ip, port, sni_name, via_proxy):
    server = None if sni_name == "none" else ip
    try:
        raw = socks5_connect((ip, port)) if via_proxy else socket.create_connection((ip, port), timeout=TIMEOUT)
    except Exception as e:
        return ("conn_fail", "", "", False, str(e)[:38])
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(raw, server_hostname=server)
        cert = ssock.getpeercert()
        ssock.close()
        if not cert:
            return ("no_cert", "", "", False, "")
        so, io = o_of(cert.get("subject", ())), o_of(cert.get("issuer", ()))
        return ("ok", so, io, "cloudflare" in so.lower(), "")
    except Exception as e:
        return ("tls_fail", "", "", False, str(e)[:46])
    finally:
        try: raw.close()
        except Exception: pass

def load_targets():
    rows = list(csv.DictReader(open(SRC, encoding="utf-8")))
    cf    = [(r["IP地址"], int(r["端口号"])) for r in rows if "13335" in (r["ASN号码"] or "")]
    noncf = [(r["IP地址"], int(r["端口号"])) for r in rows if "13335" not in (r["ASN号码"] or "")]
    random.seed(7); random.shuffle(noncf)
    return cf, noncf[:90]

def main():
    cf, noncf = load_targets()
    jobs = [(g, ip, port, sni, via) for g, grp in [("A_official", cf), ("B_target", noncf)]
            for ip, port in grp for sni in ("none", "ip") for via in (False, True)]
    # 结果归集： (group, ip) -> 各模式结果
    agg = defaultdict(list)
    stats = Counter()
    with ThreadPoolExecutor(max_workers=50) as ex:
        for res in ex.map(lambda j: j + probe(*j[1:]), jobs):
            g, ip, port, sni, via, st, so, io, cff, err = res
            stats[(g, sni, "proxy" if via else "direct", st)] += 1
            agg[(g, ip)].append((sni, via, st, so, io, cff, err))
    # 关键指标：每个 target 是否在「任意」模式下呈现 CF 证书
    print("=== 模式级汇总 (group, sni, exit, result) -> count ===")
    for k, v in sorted(stats.items()):
        print(f"  {k} -> {v}")
    print(f"\n总探针: {sum(stats.values())}")
    for g, label in [("A_official", "组A官方13335"), ("B_target", "组B第三方目标")]:
        targets = defaultdict(dict)
        for (gg, ip), recs in agg.items():
            if gg != g: continue
            for sni, via, st, so, io, cff, err in recs:
                targets[ip][(sni, via)] = (st, so, io, cff, err)
        n = len(targets)
        presented = sum(1 for ip, m in targets.items() if any(r[3] for r in m.values()))
        any_ok    = sum(1 for ip, m in targets.items() if any(r[0]=="ok" for r in m.values()))
        print(f"\n[{label}] 目标数={n}  任模式呈现CF证书={presented}  任模式握手ok={any_ok}")
        # 打印该组里"呈现CF证书"的样本（验证 ③ 主信号 subject O 分布）
        shown = 0
        for ip, m in targets.items():
            for (sni, via), (st, so, io, cff, err) in m.items():
                if cff and shown < 12:
                    print(f"   CF✓ {ip:16} sni={sni:4} {'proxy' if via else 'direct':5} subj={so!r} iss={io!r}")
                    shown += 1
                    break
    # direct vs proxy 成功率（证明出口重要性）
    for g in ("A_official", "B_target"):
        d_ok = stats[(g, "none", "direct", "ok")] + stats[(g, "ip", "direct", "ok")]
        p_ok = stats[(g, "none", "proxy", "ok")] + stats[(g, "ip", "proxy", "ok")]
        print(f"\n[{g}] 直连ok={d_ok}  代理ok={p_ok}  → 出口差异")

if __name__ == "__main__":
    main()
