1|#!/usr/bin/env bash
2|# ASNIPtest — 一键安装脚本
3|# 用法:
4|#   bash <(curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh)
5|# 或:
6|#   curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh | bash
7|set -e
8|
9|REPO_URL="https://github.com/take2be/ASNIPtest"
10|INSTALL_DIR="${HOME}/.asnip"
11|BOLD='\033[1m'
12|GREEN='\033[0;32m'
13|YELLOW='\033[1;33m'
14|RED='\033[0;31m'
15|NC='\033[0m'
16|
17|echo -e "${BOLD}========================================${NC}"
18|echo -e "${BOLD}  ASNIPtest — CF 反代 IP 优选工具${NC}"
19|echo -e "${BOLD}========================================${NC}"
20|echo ""
21|
22|24|# ---- 步骤 0: 清理旧残留 ----
25|echo -e "  ${BOLD}[0/4] 清理旧残留...${NC}"
26|rm -f /usr/local/bin/asnip 2>/dev/null || true
27|rm -f "${HOME}/.local/bin/asnip" 2>/dev/null || true
28|rm -rf "${INSTALL_DIR}/bin" 2>/dev/null || true
29|find /usr/local/bin -maxdepth 1 -name "asnip" \( -type l -o -type f \) -delete 2>/dev/null || true
30|
31|
32|# ---- 步骤 1: 检测环境 ----
33|echo -e "${BOLD}[1/4] 检测环境...${NC}"
34|OS="$(uname -s)"
35|ARCH="$(uname -m)"
36|IS_WSL=false
37|if grep -qi microsoft /proc/version 2>/dev/null; then
38|    IS_WSL=true
39|fi
40|echo "  OS: ${OS}  Arch: ${ARCH}  WSL: ${IS_WSL}"
41|
42|# sudo 检测（Docker 容器里通常没 sudo）
43|SUDO=""
44|if command -v sudo &>/dev/null; then
45|    SUDO="sudo"
46|elif [ "$(id -u)" -eq 0 ]; then
47|    # 已经是 root，不需要 sudo
48|    SUDO=""
49|else
50|    echo -e "${YELLOW}⚠ 无 sudo 且非 root，可能权限不足${NC}"
51|fi
52|
53|# Python
54|PYTHON=""
55|for cmd in python3 python; do
56|    if command -v "$cmd" &>/dev/null; then
57|        PYTHON="$(command -v "$cmd")"
58|        break
59|    fi
60|done
61|if [ -z "$PYTHON" ]; then
62|    echo -e "${RED}✗ 需要 Python 3.8+${NC}"
63|    if command -v apt &>/dev/null; then
64|        $SUDO apt install -y -qq python3
65|        PYTHON="$(command -v python3)"
66|    else
67|        exit 1
68|    fi
69|fi
70|echo -e "  Python: $($PYTHON --version)"
71|
72|# pip
73|if ! $PYTHON -m pip --version &>/dev/null; then
74|    echo -e "  ${YELLOW}⚠ pip 未安装，自动安装...${NC}"
75|    $SUDO apt update -qq 2>/dev/null || true
76|    if ! $SUDO apt install -y -qq python3-pip 2>/dev/null; then
77|        echo -e "  ${YELLOW}⚠ apt 无 python3-pip，尝试 get-pip.py...${NC}"
78|        curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py 2>/dev/null || \
79|        curl -fsSL https://www.python.org/ftp/python/3.14.0/get-pip.py -o /tmp/get-pip.py 2>/dev/null || {
80|            echo -e "${RED}✗ 无法下载 get-pip.py${NC}"
81|            exit 1
82|        }
83|        $PYTHON /tmp/get-pip.py --quiet 2>/dev/null || {
84|            echo -e "${RED}✗ pip 安装失败${NC}"
85|            exit 1
86|        }
87|    fi
88|fi
89|# PEP 668 绕过（Ubuntu 24.04+）
90|export PIP_BREAK_SYSTEM_PACKAGES=1
91|echo -e "  pip: $($PYTHON -m pip --version | head -1)"
92|echo ""
93|
94|# ---- 步骤 2: 下载项目文件 ----
95|echo -e "${BOLD}[2/4] 获取项目文件...${NC}"
96|mkdir -p "${INSTALL_DIR}/bin" "${INSTALL_DIR}/config" "${INSTALL_DIR}/src"
97|
98|SCRIPT_SRC="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
99|if [ -z "$SCRIPT_SRC" ] || [ "$SCRIPT_SRC" = "/tmp" ] || [ ! -f "$SCRIPT_SRC/install.sh" ]; then
100|    echo "  从 GitHub 下载..."
101|    # 走 tarball 下载（比 git clone 更稳过代理）
102|    mkdir -p /tmp/asnip-dl
103|    TAR_URL="https://github.com/take2be/ASNIPtest/archive/refs/heads/master.tar.gz"
104|    # GitHub tarball 下载（走 socks5 代理或在国外直连）
105|    SOCKS_ADDR=""
106|    if echo "${http_proxy}" | grep -qiE "socks|1080|10808" 2>/dev/null; then
107|        SOCKS_ADDR="$(echo "${http_proxy}" | sed 's|.*://||')"
108|    fi
109|    if command -v wget &>/dev/null; then
110|        # wget 重试更强
111|        if [ -n "$SOCKS_ADDR" ]; then
112|            wget -q -O /tmp/asnip-dl/master.tar.gz --timeout=30 --tries=3 \
113|              --no-check-certificate \
114|              "https://github.com/take2be/ASNIPtest/archive/refs/heads/master.tar.gz" 2>/dev/null || \
115|            wget -q -O /tmp/asnip-dl/master.tar.gz --timeout=30 --tries=3 \
116|              "http://github.com/take2be/ASNIPtest/archive/refs/heads/master.tar.gz" 2>/dev/null
117|        else
118|            wget -q -O /tmp/asnip-dl/master.tar.gz --timeout=30 --tries=3 \
119|              "$TAR_URL"
120|        fi
121|    elif command -v curl &>/dev/null; then
122|        if [ -n "$SOCKS_ADDR" ]; then
123|            curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 15 \
124|              --socks5-hostname "$SOCKS_ADDR" \
125|              -o /tmp/asnip-dl/master.tar.gz "$TAR_URL"
126|        else
127|            curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 15 \
128|              -o /tmp/asnip-dl/master.tar.gz "$TAR_URL"
129|        fi
130|    else
131|        echo -e "${RED}✗ 需要 curl 或 wget${NC}"
132|        exit 1
133|    fi
134|    rm -rf "${INSTALL_DIR}/src"
135|    mkdir -p "${INSTALL_DIR}/src"
136|    tar xzf /tmp/asnip-dl/master.tar.gz -C /tmp/asnip-dl/
137|    cp -r /tmp/asnip-dl/ASNIPtest-master/* "${INSTALL_DIR}/src/"
138|    rm -rf /tmp/asnip-dl
139|    echo -e "  ${GREEN}✅ 下载完成${NC}"
140|else
141|    echo "  复制: ${SCRIPT_SRC} → ${INSTALL_DIR}/src"
142|    rm -rf "${INSTALL_DIR}/src"
143|    cp -r "$SCRIPT_SRC" "${INSTALL_DIR}/src"
144|    echo -e "  ${GREEN}✅ 复制完成${NC}"
145|fi
146|
147|# 写 CF 官方 ASN 清单（保险）
148|if [ ! -f "${INSTALL_DIR}/src/config/cf_official_asns.txt" ]; then
149|    mkdir -p "${INSTALL_DIR}/src/config"
150|    cat > "${INSTALL_DIR}/src/config/cf_official_asns.txt" << 'EOF'
151|# Cloudflare 官方 ASN 清单
152|AS13335
153|AS395747
154|AS132892
155|AS202623
156|AS133877
157|AS139242
158|AS203898
159|AS394536
160|AS400095
161|AS14789
162|AS209242
163|AS204829
164|AS200242
165|EOF
166|fi
167|echo ""
168|
169|# ---- 步骤 3: Python 依赖 ----
170|echo -e "${BOLD}[3/4] 安装 Python 依赖...${NC}"
171|$PYTHON -m pip install --quiet --upgrade pip 2>/dev/null || true
172|
173|# 装 dnspython（直连 PyPI → 失败自动切国内镜像）
174|if $PYTHON -m pip install --quiet dnspython 2>/dev/null; then
175|    echo -e "  ${GREEN}✅ dnspython 就绪${NC}"
176|else
177|    echo -e "  ${YELLOW}⚠ PyPI 直连失败，尝试国内镜像...${NC}"
178|    for mirror in \
179|        "https://mirrors.huaweicloud.com/pypi/simple/" \
180|        "https://pypi.tuna.tsinghua.edu.cn/simple/" \
181|        "https://mirrors.aliyun.com/pypi/simple/"; do
182|        if $PYTHON -m pip install --quiet -i "$mirror" dnspython 2>/dev/null; then
183|            echo -e "  ${GREEN}✅ dnspython 就绪 (镜像: $mirror)${NC}"
184|            break
185|        fi
186|    done || {
187|        echo -e "${RED}✗ 无法安装 dnspython，请手动执行:${NC}"
188|        echo "  pip install dnspython"
189|        exit 1
190|    }
191|fi
192|echo ""
193|
194|# ---- 步骤 4: 外部依赖 ----
195|echo -e "${BOLD}[4/4] 安装外部依赖...${NC}"
196|
197|# masscan
198|if ! command -v masscan &>/dev/null; then
199|    echo -e "  ${YELLOW}⚠ masscan 未安装，自动安装...${NC}"
200|    $SUDO apt install -y -qq masscan
201|fi
202|# 给 masscan 加 capabilities（免 sudo 也能 raw socket）
203|$SUDO setcap cap_net_raw+ep "$(command -v masscan)" 2>/dev/null || true
204|echo -e "  ${GREEN}✅ masscan: $(masscan --version 2>&1 | head -1)${NC}"
205|
206|# cf-scanner
207|CF_SCANNER="${INSTALL_DIR}/src/cf-scanner"
208|if [ -f "$CF_SCANNER" ]; then
209|    chmod +x "$CF_SCANNER"
210|    echo -e "  ${GREEN}✅ cf-scanner: 就绪${NC}"
211|else
212|    echo -e "  ${YELLOW}⚠ cf-scanner 未找到，尝试编译...${NC}"
213|    if command -v go &>/dev/null && [ -d "${INSTALL_DIR}/src/cf-scanner-src" ]; then
214|        cd "${INSTALL_DIR}/src/cf-scanner-src"
215|        go build -o "$CF_SCANNER" . && {
216|            chmod +x "$CF_SCANNER"
217|            echo -e "  ${GREEN}✅ cf-scanner: 编译成功${NC}"
218|        } || {
219|            echo -e "  ${YELLOW}  ⚠ 编译失败${NC}"
220|        }
221|    elif [ -f "$CF_SCANNER" ]; then
222|        echo -e "  ${GREEN}✅ cf-scanner: 就绪${NC}"
223|    else
224|        echo -e "  ${YELLOW}  ⚠ cf-scanner 未找到，scan 会跳过 verify 步骤${NC}"
225|    fi
226|fi
227|echo ""
228|
229|# ---- 创建 asnip 命令（总是覆盖到最新）----
230|mkdir -p "${INSTALL_DIR}/bin"
231|cat > "${INSTALL_DIR}/bin/asnip" << SCRIPT
232|#!/usr/bin/env bash
233|DIR="${INSTALL_DIR}/src"
234|cd "\$DIR"
235|exec python3 asnip.py "\$@"
236|SCRIPT
237|chmod +x "${INSTALL_DIR}/bin/asnip"
238|
239|# 清理可能残留的旧 broken symlink
240|rm -f /usr/local/bin/asnip 2>/dev/null || true
241|
242|# 当前交互 shell 立刻生效
243|export PATH="${INSTALL_DIR}/bin:$PATH"
244|
245|# ---- 完成 ----
246|echo -e "${GREEN}${BOLD}========================================${NC}"
247|echo -e "${GREEN}${BOLD}  🎉 安装完成！${NC}"
248|echo -e "${GREEN}${BOLD}========================================${NC}"
249|echo ""
250|echo -e "  安装目录: ${INSTALL_DIR}"
251|echo -e "  运行方式: ${BOLD}asnip scan${NC}"
252|echo ""
253|echo -e "  或者:    ${BOLD}asnip scan 13335,209554${NC}"
254|echo ""
255|