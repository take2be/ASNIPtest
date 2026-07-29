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

# ---- 步骤 0: 清理旧残留 ----
echo -e "  ${BOLD}[0/4] 清理旧残留...${NC}"
rm -f /usr/local/bin/asnip 2>/dev/null || true
rm -f "${HOME}/.local/bin/asnip" 2>/dev/null || true
rm -rf "${INSTALL_DIR}/bin" 2>/dev/null || true
find /usr/local/bin -maxdepth 1 -name "asnip" \( -type l -o -type f \) -delete 2>/dev/null || true

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
cat > "${INSTALL_DIR}/bin/asnip" << SCRIPT
#!/usr/bin/env bash
DIR="${INSTALL_DIR}/src"
cd "\$DIR"
exec python3 asnip.py "\$@"
SCRIPT
chmod +x "${INSTALL_DIR}/bin/asnip"

# 清理可能残留的旧 broken symlink
rm -f /usr/local/bin/asnip 2>/dev/null || true

# 当前交互 shell 立刻生效
export PATH="${INSTALL_DIR}/bin:$PATH"

# ---- 完成 ----
echo -e "${GREEN}${BOLD}========================================${NC}"
echo -e "${GREEN}${BOLD}  🎉 安装完成！${NC}"
echo -e "${GREEN}${BOLD}========================================${NC}"
echo ""
echo -e "  安装目录: ${INSTALL_DIR}"
echo -e "  运行方式: ${BOLD}asnip scan${NC}"
echo ""
echo -e "  或者:    ${BOLD}asnip scan 13335,209554${NC}"
echo ""
