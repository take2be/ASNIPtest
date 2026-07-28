#!/usr/bin/env python3
# probe_cf.py —— 严格 import ③ 框架 verify.py 跑真实样本，禁止任何 ad-hoc ssl 代码
import csv, random
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import verify
from verify import VerifyConfig, Result, Reason

SRC = os.path.join(os.path.expanduser("~"), "AppData", "Local", "hermes", "cache", "documents", "doc_1b62c45ca5ea_Global-proxyip-443.csv")

def load():
    rows = list(csv.DictReader(open(SRC, encoding="utf-8")))
    cf    = [(r["IP地址"], int(r["端口号"])) for r in rows if "13335" in (r["ASN号码"] or "")]
    noncf = [(r["IP地址"], int(r["端口号"])) for r in rows if "13335" not in (r["ASN号码"] or "")]
    random.seed(7); random.shuffle(noncf)
    return cf, noncf[:90]

def run():
    cf, noncf = load()
    # 维度：SNI(none/ip) × 出口(direct/proxy) × 模式(hybrid/tls)
    sni_modes = [("none", None), ("ip", "IP_PLACEHOLDER")]
    exit_modes = [("direct", False), ("proxy", True)]
    jobs = [(g, ip, port, sni_name, sni_val, via)
            for g, grp in [("A_official", cf), ("B_target", noncf)]
            for ip, port in grp
            for sni_name, sni_val in sni_modes
            for via_name, via in exit_modes]
    stats = Counter()
    agg = defaultdict(dict)   # (g,ip) -> {(sni,via): result}
    def do(j):
        g, ip, port, sni_name, sni_val, via = j
        cfg = VerifyConfig(sni=(ip if sni_val == "IP_PLACEHOLDER" else None), use_proxy=via)
        res = verify.verify(ip, port, cfg, mode="hybrid")
        return (g, ip, sni_name, via, res)
    with ThreadPoolExecutor(max_workers=50) as ex:
        for r in ex.map(do, jobs):
            g, ip, sni_name, via, res = r
            stats[(g, sni_name, "proxy" if via else "direct", res.result, res.reason)] += 1
            agg[(g, ip)][(sni_name, via)] = res
    print("=== 模式级汇总 (group, sni, exit, result, reason) -> count ===")
    for k, v in sorted(stats.items()):
        print(f"  {k} -> {v}")
    print(f"\n总探针: {sum(stats.values())}")
    for g, label in [("A_official", "组A官方13335"), ("B_target", "组B第三方目标")]:
        targets = defaultdict(dict)
        for (gg, ip), m in agg.items():
            if gg == g: targets[ip] = m
        n = len(targets)
        # 任一模式判定为 CF（PASS）的目标数 —— 注意：设计主信号=subject O 含cloudflare
        cf_pass = sum(1 for ip, m in targets.items()
                      if any(r.result == Result.PASS for r in m.values()))
        # 诊断：任一模式出现「有证但 O 不含cf」(TLS_NO_MATCH 且 cert 可见) 的目标数
        cn_san_cf = sum(1 for ip, m in targets.items()
                        if any(r.extras.get("_diag_cf_in_cn_san") for r in m.values()))
        print(f"\n[{label}] 目标数={n}  hybrid任模式PASS={cf_pass}  证书CN/SAN含cloudflare={cn_san_cf}")
        # 打印若干细节（subject O / CN / SAN 实测值）
        shown = 0
        for ip, m in targets.items():
            for (sni, via), r in m.items():
                if r.extras.get("subj_o") is not None or r.extras.get("cn"):
                    if shown < 10:
                        print(f"   {ip:16} sni={sni:4} {'proxy' if via else 'direct':5} "
                              f"res={r.result.value:7} reason={r.reason.value:14} "
                              f"subjO={r.extras.get('subj_o','')!r} cn={r.extras.get('cn','')!r} "
                              f"san={r.extras.get('san','')[:2]}")
                        shown += 1
                    break

if __name__ == "__main__":
    run()
