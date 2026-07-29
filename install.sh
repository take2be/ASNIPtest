#!/usr/bin/env bash
# ASNIPtest — 一键安装脚本
# 用法:
#   bash <(curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh)
# 或:
#   curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh | bash
set -e

REPO_URL="https://github.com/take2be/ASNIPtest"
INSTALL_DIR="${HOME}/.asnip"
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}  ASNIPtest — CF 反代 IP 优选工具${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# ---- 步骤 1: 检测环境 ----
echo -e "${BOLD}[1/4] 检测环境...${NC}"
OS="$(uname -s)"
ARCH="$(uname -m)"
IS_WSL=false
if grep -qi microsoft /proc/version 2>/dev/null; then
    IS_WSL=true
fi
echo "  OS: ${OS}  Arch: ${ARCH}  WSL: ${IS_WSL}"

# sudo 检测（Docker 容器里通常没 sudo）
SUDO=""
if command -v sudo &>/dev/null; then
    SUDO="sudo"
elif [ "$(id -u)" -eq 0 ]; then
    # 已经是 root，不需要 sudo
    SUDO=""
else
    echo -e "${YELLOW}⚠ 无 sudo 且非 root，可能权限不足${NC}"
fi

# Python
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$(command -v "$cmd")"
        break
    fi
done
if [ -z "$PYTHON" ]; then
    echo -e "${RED}✗ 需要 Python 3.8+${NC}"
    if command -v apt &>/dev/null; then
        $SUDO apt install -y -qq python3
        PYTHON="$(command -v python3)"
    else
        exit 1
    fi
fi
echo -e "  Python: $($PYTHON --version)"

# pip
if ! $PYTHON -m pip --version &>/dev/null; then
    echo -e "  ${YELLOW}⚠ pip 未安装，自动安装...${NC}"
    $SUDO apt update -qq 2>/dev/null || true
    if ! $SUDO apt install -y -qq python3-pip 2>/dev/null; then
        echo -e "  ${YELLOW}⚠ apt 无 python3-pip，尝试 get-pip.py...${NC}"
        curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py 2>/dev/null || \
        curl -fsSL https://www.python.org/ftp/python/3.14.0/get-pip.py -o /tmp/get-pip.py 2>/dev/null || {
            echo -e "${RED}✗ 无法下载 get-pip.py${NC}"
            exit 1
        }
        $PYTHON /tmp/get-pip.py --quiet 2>/dev/null || {
            echo -e "${RED}✗ pip 安装失败${NC}"
            exit 1
        }
    fi
fi
# PEP 668 绕过（Ubuntu 24.04+）
export PIP_BREAK_SYSTEM_PACKAGES=1
echo -e "  pip: $($PYTHON -m pip --version | head -1)"
echo ""

# ---- 步骤 2: 下载项目文件 ----
echo -e "${BOLD}[2/4] 获取项目文件...${NC}"
mkdir -p "${INSTALL_DIR}/bin" "${INSTALL_DIR}/config" "${INSTALL_DIR}/src"

SCRIPT_SRC="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
if [ -z "$SCRIPT_SRC" ] || [ "$SCRIPT_SRC" = "/tmp" ] || [ ! -f "$SCRIPT_SRC/install.sh" ]; then
    echo "  从 GitHub 下载..."
    # 走 tarball 下载（比 git clone 更稳过代理）
    mkdir -p /tmp/asnip-dl
    TAR_URL="https://github.com/take2be/ASNIPtest/archive/refs/heads/master.tar.gz"
    # GitHub tarball 下载（走 socks5 代理或在国外直连）
    SOCKS_ADDR=""
    if echo "${http_proxy}" | grep -qiE "socks|1080|10808" 2>/dev/null; then
        SOCKS_ADDR="$(echo "${http_proxy}" | sed 's|.*://||')"
    fi
    if command -v wget &>/dev/null; then
        # wget 重试更强
        if [ -n "$SOCKS_ADDR" ]; then
            wget -q -O /tmp/asnip-dl/master.tar.gz --timeout=30 --tries=3 \
              --no-check-certificate \
              "https://github.com/take2be/ASNIPtest/archive/refs/heads/master.tar.gz" 2>/dev/null || \
            wget -q -O /tmp/asnip-dl/master.tar.gz --timeout=30 --tries=3 \
              "http://github.com/take2be/ASNIPtest/archive/refs/heads/master.tar.gz" 2>/dev/null
        else
            wget -q -O /tmp/asnip-dl/master.tar.gz --timeout=30 --tries=3 \
              "$TAR_URL"
        fi
    elif command -v curl &>/dev/null; then
        if [ -n "$SOCKS_ADDR" ]; then
            curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 15 \
              --socks5-hostname "$SOCKS_ADDR" \
              -o /tmp/asnip-dl/master.tar.gz "$TAR_URL"
        else
            curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 15 \
              -o /tmp/asnip-dl/master.tar.gz "$TAR_URL"
        fi
    else
        echo -e "${RED}✗ 需要 curl 或 wget${NC}"
        exit 1
    fi
    rm -rf "${INSTALL_DIR}/src"
    mkdir -p "${INSTALL_DIR}/src"
    tar xzf /tmp/asnip-dl/master.tar.gz -C /tmp/asnip-dl/
    cp -r /tmp/asnip-dl/ASNIPtest-master/* "${INSTALL_DIR}/src/"
    rm -rf /tmp/asnip-dl
    echo -e "  ${GREEN}✅ 下载完成${NC}"
else
    echo "  复制: ${SCRIPT_SRC} → ${INSTALL_DIR}/src"
    rm -rf "${INSTALL_DIR}/src"
    cp -r "$SCRIPT_SRC" "${INSTALL_DIR}/src"
    echo -e "  ${GREEN}✅ 复制完成${NC}"
fi

# 写 CF 官方 ASN 清单（保险）
if [ ! -f "${INSTALL_DIR}/src/config/cf_official_asns.txt" ]; then
    mkdir -p "${INSTALL_DIR}/src/config"
    cat > "${INSTALL_DIR}/src/config/cf_official_asns.txt" << 'EOF'
# Cloudflare 官方 ASN 清单
AS13335
AS395747
AS132892
AS202623
AS133877
AS139242
AS203898
AS394536
AS400095
AS14789
AS209242
AS204829
AS200242
EOF
fi
echo ""

# ---- 步骤 3: Python 依赖 ----
echo -e "${BOLD}[3/4] 安装 Python 依赖...${NC}"
$PYTHON -m pip install --quiet --upgrade pip 2>/dev/null || true

# 装 dnspython（直连 PyPI → 失败自动切国内镜像）
if $PYTHON -m pip install --quiet dnspython 2>/dev/null; then
    echo -e "  ${GREEN}✅ dnspython 就绪${NC}"
else
    echo -e "  ${YELLOW}⚠ PyPI 直连失败，尝试国内镜像...${NC}"
    for mirror in \
        "https://mirrors.huaweicloud.com/pypi/simple/" \
        "https://pypi.tuna.tsinghua.edu.cn/simple/" \
        "https://mirrors.aliyun.com/pypi/simple/"; do
        if $PYTHON -m pip install --quiet -i "$mirror" dnspython 2>/dev/null; then
            echo -e "  ${GREEN}✅ dnspython 就绪 (镜像: $mirror)${NC}"
            break
        fi
    done || {
        echo -e "${RED}✗ 无法安装 dnspython，请手动执行:${NC}"
        echo "  pip install dnspython"
        exit 1
    }
fi
echo ""

# ---- 步骤 4: 外部依赖 ----
echo -e "${BOLD}[4/4] 安装外部依赖...${NC}"

# masscan
if ! command -v masscan &>/dev/null; then
    echo -e "  ${YELLOW}⚠ masscan 未安装，自动安装...${NC}"
    $SUDO apt install -y -qq masscan
fi
# 给 masscan 加 capabilities（免 sudo 也能 raw socket）
$SUDO setcap cap_net_raw+ep "$(command -v masscan)" 2>/dev/null || true
echo -e "  ${GREEN}✅ masscan: $(masscan --version 2>&1 | head -1)${NC}"

# cf-scanner
CF_SCANNER="${INSTALL_DIR}/src/cf-scanner"
if [ -f "$CF_SCANNER" ]; then
    chmod +x "$CF_SCANNER"
    echo -e "  ${GREEN}✅ cf-scanner: 就绪${NC}"
else
    echo -e "  ${YELLOW}⚠ cf-scanner 未找到，尝试编译...${NC}"
    if command -v go &>/dev/null && [ -d "${INSTALL_DIR}/src/cf-scanner-src" ]; then
        cd "${INSTALL_DIR}/src/cf-scanner-src"
        go build -o "$CF_SCANNER" . && {
            chmod +x "$CF_SCANNER"
            echo -e "  ${GREEN}✅ cf-scanner: 编译成功${NC}"
        } || {
            echo -e "  ${YELLOW}  ⚠ 编译失败${NC}"
        }
    elif [ -f "$CF_SCANNER" ]; then
        echo -e "  ${GREEN}✅ cf-scanner: 就绪${NC}"
    else
        echo -e "  ${YELLOW}  ⚠ cf-scanner 未找到，scan 会跳过 verify 步骤${NC}"
    fi
fi
echo ""

# ---- 创建 asnip 命令（总是覆盖到最新）----
mkdir -p "${INSTALL_DIR}/bin"
{
  echo '#!/usr/bin/env bash'
  echo 'DIR="$(cd "$(dirname "$0")/../src" && pwd)"'
  echo 'cd "$DIR"'
  echo 'exec python3 asnip.py "$@"'
} > "${INSTALL_DIR}/bin/asnip"
chmod +x "${INSTALL_DIR}/bin/asnip"

{
  echo '#!/usr/bin/env bash'
  echo 'DIR="$(cd "$(dirname "$0")/../src" && pwd)"'
  echo 'cd "$DIR"'
  echo 'exec python3 asnip.py scan "$@"'
} > "${INSTALL_DIR}/bin/ips"
chmod +x "${INSTALL_DIR}/bin/ips"

# 清理可能残留的旧 broken symlink
rm -f /usr/local/bin/asnip /usr/local/bin/ips 2>/dev/null || true

# 当前交互 shell 立刻生效
export PATH="${INSTALL_DIR}/bin:$PATH"

# ---- 注册 irds / irds-result 到 ~/.asnip/bin/（开箱即用，无需 source） ----
BIN_DIR="${INSTALL_DIR}/bin"
mkdir -p "$BIN_DIR"

# irds 脚本
cat > "$BIN_DIR/irds" << 'SCRIPT'
#!/usr/bin/env bash
args="$*"
if command -v screen >/dev/null 2>&1 && screen -list 2>/dev/null | grep -q '(asnip)'; then
    echo "  检测到已有 asnip screen session，先用 screen -r asnip 查看"
    exit 0
fi
if command -v tmux >/dev/null 2>&1 && tmux has-session -t asnip 2>/dev/null; then
    echo "  检测到已有 asnip tmux session，先用 tmux attach -t asnip 查看"
    exit 0
fi
runner=""
if command -v screen >/dev/null 2>&1; then
    runner="screen"
elif command -v tmux >/dev/null 2>&1; then
    runner="tmux"
else
    echo "  未检测到 screen/tmux，直接前台运行 --daemon"
    exec ips --daemon $args
fi
inner_cmd="trap '' HUP; while true; do ips --daemon $args; code=\$?; if [ \$code -eq 0 ]; then if [ -f \"${HOME}/.asnip/src/scan_data/report.csv\" ]; then echo \"报告文件已生成: ${HOME}/.asnip/src/scan_data/report.csv\"; break; fi; fi; echo \"上次执行结束(exit=\$code)且未见 report.csv，10秒后自动续跑...\"; sleep 10; done"
if [ "$runner" = "screen" ]; then
    screen -dmS asnip bash -c "$inner_cmd"
    sleep 0.5
    screen -r asnip
else
    tmux new-session -d -s asnip bash -c "$inner_cmd"
    tmux attach -t asnip
fi
disown 2>/dev/null || true
echo "  已在后台启动(screen session: asnip，daemon 守护模式)"
echo "  看进度: screen -r asnip      (Ctrl+A D  detached 返回)"
echo "  查结果: irds-result"
SCRIPT
chmod +x "$BIN_DIR/irds"

# irds-result 脚本
cat > "$BIN_DIR/irds-result" << 'SCRIPT'
#!/usr/bin/env bash
rpt=""
if [ -d "${HOME}/.asnip/src/scan_data" ]; then
    rpt=$(find "${HOME}/.asnip/src/scan_data" -maxdepth 1 -name "report.csv" -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
fi
if [ -z "$rpt" ] || [ ! -f "$rpt" ]; then
    echo "  尚未找到 report.csv"
    exit 1
fi
echo "  报告: $rpt"
python3 - "$rpt" << 'PY'
import csv, sys
p = sys.argv[1]
rows = []
with open(p, newline='', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)
    for r in reader:
        rows.append(r)
if not rows:
    print("  空报告")
    sys.exit(0)
valid = [r for r in rows if r.get('Latency_ms','-') not in ('-','')]
print(f"  总行: {len(rows)}，有效: {len(valid)}")
if valid:
    valid_sorted = sorted(valid, key=lambda r: (float(r.get('Latency_ms', 99999) or 99999), -float(r.get('Download_Mbps', 0) or 0)))
    print("  Top 10 可用:")
    print("  %-18s %-8s %10s %12s %10s" % ("IP:PORT", "Country", "Latency", "Download", "Org"))
    for r in valid_sorted[:10]:
        ip = r.get('IP','?')
        port = r.get('PORT','?')
        print("  %-18s %-8s %8sms %10sMbps %10s" % (
            f"{ip}:{port}",
            r.get('Country','-')[:8],
            r.get('Latency_ms','-'),
            r.get('Download_Mbps', 0),
            (r.get('Org','-')[:10] or '-'),
        ))
PY
SCRIPT
chmod +x "$BIN_DIR/irds-result"

echo -e " ${GREEN}✅ irds / irds-result 已注册到 $BIN_DIR/${NC}"

# ---- 完成 ----
echo -e "${GREEN}${BOLD}========================================${NC}"
echo -e "${GREEN}${BOLD}  🎉 安装完成！${NC}"
echo -e "${GREEN}${BOLD}========================================${NC}"
echo ""
echo -e "  安装目录: ${INSTALL_DIR}"
echo ""
echo -e "  常用命令："
echo -e "    ${BOLD}irds <ASN>${NC}         启动扫描，自动后台 + 自动续跑 + 自动进入进度界面"
echo -e "    ${BOLD}irds-result${NC}       查看最近一次扫描结果（可用 IP 汇总）"
echo -e "    ${BOLD}screen -r asnip${NC}    查看当前扫描进度"
echo -e "    ${BOLD}Ctrl+A D${NC}           detach 返回主 shell，任务继续跑"
echo ""
