#!/usr/bin/env bash
# ASNIPtest — 一键安装脚本
# 用法:
#   bash <(curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh)
# 或:
#   curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh | bash
set -e

# 安装结束时清理遗留的裸奔面板进程。
# 面板不再常驻：它只在 attach 进 screen 会话时启动（一次性 token），
# detach 立即关闭端口 —— 公网上没有长期开放的无鉴权端口。
_restart_panel() {
    # 面板不再随安装常驻：它只在 attach 进 screen 会话时启动（一次性 token），
    # detach 即关闭端口。这里只确保没有遗留的旧面板进程在裸奔。
    pkill -f "progress_server\.py" 2>/dev/null || true
    return 0
}
trap '_restart_panel' EXIT

REPO_URL="https://github.com/take2be/ASNIPtest"
INSTALL_DIR="${HOME}/.asnip"
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo "  提示：SSH 不稳定时先用 screen -S asnip-install 再跑本脚本"
echo "        断连后重连执行 screen -r 可恢复查看进度"
echo ""

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
    echo -e "${YELLOW}[WARN] 无 sudo 且非 root，可能权限不足${NC}"
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
    echo -e "${RED}[ERR] 需要 Python 3.8+${NC}"
    if command -v apt &>/dev/null; then
        $SUDO apt install -y -qq python3
        PYTHON="$(command -v python3)"
    else
        exit 1
    fi
fi
echo -e "  Python: $($PYTHON --version)"

# pip
# 先切到稳定目录再碰 pip（修复 shell cwd 指向已删除目录时 os.getcwd() 崩溃）
cd "$HOME" 2>/dev/null || cd / 2>/dev/null || true
if ! $PYTHON -m pip --version &>/dev/null; then
    echo -e "  ${YELLOW}[WARN] pip 未安装，自动安装...${NC}"
    $SUDO apt update -qq 2>/dev/null || true
    if ! $SUDO apt install -y -qq python3-pip 2>/dev/null; then
        echo -e "  ${YELLOW}[WARN] apt 无 python3-pip，尝试 get-pip.py...${NC}"
        curl -fsSL https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py 2>/dev/null || \
        curl -fsSL https://www.python.org/ftp/python/3.14.0/get-pip.py -o /tmp/get-pip.py 2>/dev/null || {
            echo -e "${RED}[ERR] 无法下载 get-pip.py${NC}"
            exit 1
        }
        $PYTHON /tmp/get-pip.py --quiet 2>/dev/null || {
            echo -e "${RED}[ERR] pip 安装失败${NC}"
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
    # GitHub tarball 下载（走 socks5 代理或在国外直连）
    SOCKS_ADDR=""
    if echo "${http_proxy}" | grep -qiE "socks|1080|10808" 2>/dev/null; then
        SOCKS_ADDR="$(echo "${http_proxy}" | sed 's|.*://||')"
    fi

    # ---- 先解析 master 的 commit SHA，按 SHA 下载归档 ----
    # 按分支名的归档（archive/refs/heads/master.tar.gz）缓存键就是分支名，
    # force-push 后 CDN 可能继续返回旧内容 → 装出来不是最新版。
    # 按 commit SHA 的归档是不可变的，永远拿到确定的那一版。
    REMOTE_SHA=""
    _curl_sha() {
        if [ -n "$SOCKS_ADDR" ]; then
            curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 \
              --socks5-hostname "$SOCKS_ADDR" "$1" 2>/dev/null
        else
            curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 "$1" 2>/dev/null
        fi
    }
    if command -v git &>/dev/null; then
        REMOTE_SHA="$(git ls-remote https://github.com/take2be/ASNIPtest.git \
                        refs/heads/master 2>/dev/null | cut -f1 | head -1)"
    fi
    if [ -z "$REMOTE_SHA" ] && command -v curl &>/dev/null; then
        REMOTE_SHA="$(_curl_sha "https://api.github.com/repos/take2be/ASNIPtest/commits/master" \
                      | grep -oE '"sha"[[:space:]]*:[[:space:]]*"[a-f0-9]{40}"' | head -1 \
                      | grep -oE '[a-f0-9]{40}')"
    fi
    if [ -n "$REMOTE_SHA" ]; then
        TAR_URL="https://github.com/take2be/ASNIPtest/archive/${REMOTE_SHA}.tar.gz"
        SRC_DIRNAME="ASNIPtest-${REMOTE_SHA}"
        echo "  目标版本: ${REMOTE_SHA:0:7}"
    else
        # 拿不到 SHA（无 git 且 API 不可达）：退回分支归档，并提示可能命中缓存
        TAR_URL="https://github.com/take2be/ASNIPtest/archive/refs/heads/master.tar.gz"
        SRC_DIRNAME="ASNIPtest-master"
        echo -e "  ${YELLOW}[WARN] 无法解析 commit SHA，退回分支归档${NC}"
        echo -e "  ${YELLOW}       若装出来不是最新版，等 5 分钟后重试${NC}"
    fi
    if command -v wget &>/dev/null; then
        # wget 重试更强
        if [ -n "$SOCKS_ADDR" ]; then
            wget -q -O /tmp/asnip-dl/master.tar.gz --timeout=30 --tries=3 \
              --no-check-certificate "$TAR_URL" 2>/dev/null || \
            wget -q -O /tmp/asnip-dl/master.tar.gz --timeout=30 --tries=3 \
              "$(echo "$TAR_URL" | sed 's|^https:|http:|')" 2>/dev/null
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
        echo -e "${RED}[ERR] 需要 curl 或 wget${NC}"
        exit 1
    fi
    rm -rf "${INSTALL_DIR}/src"
    mkdir -p "${INSTALL_DIR}/src"

    # 下载完成后校验 tar.gz 是否真的下载成功/非空，避免 tar 报不友好的错误
    if [ ! -s /tmp/asnip-dl/master.tar.gz ]; then
        echo -e "${RED}[ERR] 下载失败：master.tar.gz 为空或不存在，请检查网络/代理后重试${NC}"
        exit 1
    fi

    tar xzf /tmp/asnip-dl/master.tar.gz -C /tmp/asnip-dl/
    # 校验解压产物存在且 src 拷贝成功（防止 tarball 目录名不符导致静默失败）
    # 目录名随下载方式变化：按 SHA 是 ASNIPtest-<40位sha>，按分支是 ASNIPtest-master
    SRC_ROOT="/tmp/asnip-dl/${SRC_DIRNAME}"
    if [ ! -d "$SRC_ROOT" ]; then
        SRC_ROOT="$(find /tmp/asnip-dl -maxdepth 1 -type d -name 'ASNIPtest-*' | head -1)"
    fi
    if [ -z "$SRC_ROOT" ] || [ ! -d "$SRC_ROOT" ]; then
        echo -e "${RED}[ERR] 解压目录名不匹配 (ASNIPtest-* 未找到)${NC}"
        ls -la /tmp/asnip-dl/ 2>/dev/null | head -5
        exit 1
    fi
    cp -r "$SRC_ROOT"/* "${INSTALL_DIR}/src/"
    if [ ! -f "${INSTALL_DIR}/src/progress_server.py" ]; then
        echo -e "${RED}[ERR] 拷贝后 progress_server.py 缺失，安装中止${NC}"
        exit 1
    fi
    # 记录已安装版本（irds -version 读取，用于核对是否为最新）
    {
        echo "commit=${REMOTE_SHA:-unknown}"
        echo "source=$TAR_URL"
        echo "installed_at=$(date '+%Y-%m-%d %H:%M:%S %z')"
    } > "${INSTALL_DIR}/src/.version"
    rm -rf /tmp/asnip-dl
    if [ -n "$REMOTE_SHA" ]; then
        echo -e "  ${GREEN}[OK] 下载完成 (${REMOTE_SHA:0:7})${NC}"
    else
        echo -e "  ${GREEN}[OK] 下载完成${NC}"
    fi
else
    echo "  复制: ${SCRIPT_SRC} → ${INSTALL_DIR}/src"
    rm -rf "${INSTALL_DIR}/src"
    cp -r "$SCRIPT_SRC" "${INSTALL_DIR}/src"
    # 本地目录安装：如果是 git 仓库就记录本地 HEAD
    _LOCAL_SHA="$(git -C "$SCRIPT_SRC" rev-parse HEAD 2>/dev/null || echo local)"
    {
        echo "commit=${_LOCAL_SHA}"
        echo "source=local:${SCRIPT_SRC}"
        echo "installed_at=$(date '+%Y-%m-%d %H:%M:%S %z')"
    } > "${INSTALL_DIR}/src/.version"
    echo -e "  ${GREEN}[OK] 复制完成${NC}"
fi

# 面板/下载服务的访问令牌不再在安装时生成。
# 令牌是 **一次性** 的：每次 attach 进 screen 会话时随机生成并打印到你的
# 终端，detach 即失效。这样令牌不落盘、不进日志、不进 ps 命令行。
rm -f "${INSTALL_DIR}/src/access.token" 2>/dev/null || true

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

# ---- GeoLite2 mmdb 下载（enrich 主数据源；无 key 时回退 ip-api 在线源）----
# Key 与 mmdb 缓存放在安装目录之外（~/.config/asnip），卸载默认保留，
# 反复卸载重装时自动复用：不再询问 License Key、不再重复下载 77MB 库。
# 卸载时脚本会问一句是否连 Key 一起删。
ASNIP_CRED_DIR="${HOME}/.config/asnip"
MM_KEY_FILE="${ASNIP_CRED_DIR}/maxmind.key"
MM_MMDB_CACHE="${ASNIP_CRED_DIR}/mmdb"
GEOLITE2_DIR="${INSTALL_DIR}/src/data"
if [ -f "${GEOLITE2_DIR}/GeoLite2-City.mmdb" ] && [ -f "${GEOLITE2_DIR}/GeoLite2-ASN.mmdb" ]; then
    echo -e "  ${GREEN}[OK] GeoLite2 已就绪 (data/)${NC}"
elif [ -f "${MM_MMDB_CACHE}/GeoLite2-City.mmdb" ] \
     && [ -f "${MM_MMDB_CACHE}/GeoLite2-ASN.mmdb" ]; then
    # 命中本地缓存：直接复用，不联网、不问 key
    mkdir -p "${GEOLITE2_DIR}"
    cp "${MM_MMDB_CACHE}/GeoLite2-City.mmdb" "${MM_MMDB_CACHE}/GeoLite2-ASN.mmdb" "${GEOLITE2_DIR}/" 2>/dev/null
    echo -e "  ${GREEN}[OK] GeoLite2 复用本地缓存${NC}"
    # 缓存超过 30 天时问一次是否重新下载最新库（MaxMind 每周二更新）
    CACHE_AGE_DAYS=$(( ( $(date +%s) - $(stat -c %Y "${MM_MMDB_CACHE}/GeoLite2-City.mmdb" 2>/dev/null || date +%s) ) / 86400 ))
    if [ "$CACHE_AGE_DAYS" -ge 30 ] && exec 3<>/dev/tty 2>/dev/null; then
        printf "  ${BOLD}本地库已 ${CACHE_AGE_DAYS} 天未更新，现在重新下载吗？(y/N): ${NC}" >&3
        read -r DO_REFRESH <&3
        exec 3<&- 3>&- 2>/dev/null || true
        case "$DO_REFRESH" in
            y|Y|yes|YES) rm -f "${MM_MMDB_CACHE}"/GeoLite2-*.mmdb "${GEOLITE2_DIR}"/GeoLite2-*.mmdb 2>/dev/null
                         MM_NEED_DOWNLOAD=1 ;;
        esac
    fi
fi
if [ ! -f "${GEOLITE2_DIR}/GeoLite2-City.mmdb" ] || [ ! -f "${GEOLITE2_DIR}/GeoLite2-ASN.mmdb" ]; then
    # 交互向导：优先用 /dev/tty 读写（一键 curl|bash 时 stdin 是管道，
    # 但 /dev/tty 仍指向用户终端，可交互）；终端不可用时走已存 key/ip-api 兜底
    MM_LICENSE_KEY="${MM_LICENSE_KEY:-}"
    if [ -z "$MM_LICENSE_KEY" ] && [ -f "$MM_KEY_FILE" ]; then
        # 复用已保存的 key（上次安装时输入过），不再打扰用户
        MM_LICENSE_KEY="$(head -1 "$MM_KEY_FILE" 2>/dev/null | tr -d ' \t\r\n')"
        [ -n "$MM_LICENSE_KEY" ] && echo -e "  ${GREEN}[OK] 复用已保存的 MaxMind License Key${NC}"
    fi
    if [ -n "$MM_LICENSE_KEY" ]; then
        :  # 已有 key，直接用
    else
        MM_LICENSE_KEY=""
        # 尝试打开 /dev/tty 判断是否有用户终端可交互
        if exec 3<>/dev/tty 2>/dev/null; then
            echo ""
            echo -e "  ${BOLD}IP 归属数据源（enrich 阶段）${NC}"
            echo -e "    默认用 MaxMind GeoLite2 本地库（离线、零限流、含中文/大陆/国旗）。"
            echo -e "    免费获取 License Key（约 2 分钟）："
            echo -e "      注册:  https://www.maxmind.com/en/geolite2/signup"
            echo -e "      取Key: https://www.maxmind.com/en/accounts/current/license-key"
            while true; do
                printf "  ${BOLD}现在配置 GeoLite2 吗？(y/n，n 则用 ip-api 在线源): ${NC}" >&3
                read -r REQ <&3
                case "$REQ" in
                    y|Y|yes|YES)
                        printf "  ${BOLD}请输入 License Key: ${NC}" >&3
                        read -r MM_LICENSE_KEY <&3
                        echo "" >&3
                        break
                        ;;
                    n|N|no|NO)
                        MM_LICENSE_KEY=""
                        echo -e "  ${YELLOW}    已选择跳过，enrich 将用 ip-api 在线源（有限流）${NC}" >&3
                        break
                        ;;
                    *)
                        echo -e "  ${YELLOW}    请输入 y 或 n${NC}" >&3
                        ;;
                esac
            done
            exec 3<&- 3>&- 2>/dev/null || true
        else
            echo -e "  ${YELLOW}[非交互安装] 无终端可用，跳过 GeoLite2（将用 ip-api 兜底）${NC}"
        fi
    fi
    if [ -n "$MM_LICENSE_KEY" ]; then
        # 保存 key 供后续重装复用。`>` 是整文件覆盖写（非追加），
        # 文件恒为单行单 key，换 key 直接盖掉旧的，不会累积。
        mkdir -p "${ASNIP_CRED_DIR}" 2>/dev/null
        printf '%s\n' "$MM_LICENSE_KEY" > "$MM_KEY_FILE" 2>/dev/null
        chmod 600 "$MM_KEY_FILE" 2>/dev/null || true
        echo -e "  ${BOLD}下载 GeoLite2-City / GeoLite2-ASN (MaxMind)...${NC}"
        mkdir -p "${GEOLITE2_DIR}" "${MM_MMDB_CACHE}"
        DL_OK=true
        for EDITION in GeoLite2-City GeoLite2-ASN; do
            URL="https://download.maxmind.com/app/geoip_download?edition_id=${EDITION}&license_key=${MM_LICENSE_KEY}&suffix=tar.gz"
            if curl -fsSL "$URL" -o "/tmp/${EDITION}.tar.gz" 2>/dev/null; then
                tar -xzf "/tmp/${EDITION}.tar.gz" -C "/tmp" 2>/dev/null
                # 解压出的目录名为 GeoLite2-City_YYYYMMDD，取其中 .mmdb 拷到 data/
                MMDB=$(find /tmp -maxdepth 2 -name "${EDITION}.mmdb" | head -1)
                if [ -n "$MMDB" ]; then
                    cp "$MMDB" "${GEOLITE2_DIR}/${EDITION}.mmdb"
                    # 同时存入缓存，下次重装直接复用不再下载
                    cp "$MMDB" "${MM_MMDB_CACHE}/${EDITION}.mmdb" 2>/dev/null || true
                    echo -e "  ${GREEN}[OK] ${EDITION}.mmdb 就绪${NC}"
                else
                    echo -e "  ${YELLOW}[WARN] ${EDITION} 解压后未找到 mmdb${NC}"
                    DL_OK=false
                fi
                rm -f "/tmp/${EDITION}.tar.gz"
                # 清掉解压出的 GeoLite2-City_YYYYMMDD/ 目录（每个约 80MB），
                # 否则每次安装都会在 /tmp 堆一份
                rm -rf /tmp/${EDITION}_* 2>/dev/null || true
            else
                echo -e "  ${YELLOW}[WARN] ${EDITION} 下载失败（license key 无效或网络问题）${NC}"
                DL_OK=false
            fi
        done
        if [ "$DL_OK" = false ]; then
            echo -e "  ${YELLOW}  enrich 将回退 ip-api 在线源；后续可把 .mmdb 放 ${GEOLITE2_DIR} 后重跑 install.sh${NC}"
        fi
    else
        echo -e "  ${YELLOW}[WARN] 未提供 License Key，enrich 将用 ip-api 在线源（有限流）${NC}"
    fi
fi
echo ""

# ---- 步骤 3: Python 依赖 ----
echo -e "${BOLD}[3/4] 安装 Python 依赖...${NC}"
# 先切到稳定目录再跑 pip（修复 cwd 被删后 pip 启动崩溃: os.getcwd() FileNotFoundError）
cd "$HOME" || cd /
$PYTHON -m pip install --quiet --upgrade pip 2>/dev/null || true

# 装 maxminddb（GeoLite2 本地库读取；直连 PyPI → 失败自动切国内镜像）
MAXMINDDB_OK=false
if $PYTHON -m pip install --quiet maxminddb 2>/dev/null; then
    MAXMINDDB_OK=true
    echo -e "  ${GREEN}[OK] maxminddb 就绪${NC}"
else
    echo -e "  ${YELLOW}[WARN] PyPI 直连失败，尝试国内镜像...${NC}"
    for mirror in \
        "https://mirrors.huaweicloud.com/pypi/simple/" \
        "https://pypi.tuna.tsinghua.edu.cn/simple/" \
        "https://mirrors.aliyun.com/pypi/simple/"; do
        if $PYTHON -m pip install --quiet -i "$mirror" maxminddb 2>/dev/null; then
            MAXMINDDB_OK=true
            echo -e "  ${GREEN}[OK] maxminddb 就绪 (镜像: $mirror)${NC}"
            break
        fi
    done
fi
# 用显式标志位判断，比 `for ... done || {...}` 可靠（for 退出码只反映末次迭代）
if [ "$MAXMINDDB_OK" = false ]; then
    echo -e "${RED}[ERR] 无法安装 maxminddb，请手动执行:${NC}"
    echo "  pip install maxminddb"
    exit 1
fi
echo ""

# ---- 步骤 4: 外部依赖 ----
echo -e "${BOLD}[4/4] 安装外部依赖...${NC}"

# 自动依赖安装仅适配 apt 系发行版；非 apt 系统（macOS/CentOS/Alpine 等）请自行确保 python3/pip/masscan 已安装
if ! command -v apt &>/dev/null; then
    echo -e "  ${YELLOW}[WARN] 未检测到 apt，本脚本的自动依赖安装仅适配 apt 系发行版，请自行确保 python3/pip/masscan 已安装${NC}"
fi

# masscan
if ! command -v masscan &>/dev/null; then
    echo -e "  ${YELLOW}[WARN] masscan 未安装，自动安装...${NC}"
    # 原写法在 set -e 下一旦安装失败会直接中断脚本且无明确原因，这里改为捕获并提示
    if ! $SUDO apt install -y -qq masscan 2>/dev/null; then
        echo -e "${YELLOW}  [WARN] masscan 安装失败（可能权限不足或 apt 源不可用），scan 功能可能受限，请手动安装后重试${NC}"
    fi
fi
# 给 masscan 加 capabilities（免 sudo 也能 raw socket）
if command -v masscan &>/dev/null; then
    $SUDO setcap cap_net_raw+ep "$(command -v masscan)" 2>/dev/null || true
    echo -e "  ${GREEN}[OK] masscan: $(masscan --version 2>&1 | head -1)${NC}"
else
    echo -e "  ${YELLOW}[WARN] masscan 未安装，scan 功能将不可用，请手动安装后重试${NC}"
fi

# 检查 Python 版本：代码用了 3.10 的 X | Y 类型注解，低版本直接 SyntaxError
if command -v python3 &>/dev/null; then
    PY_OK="$(python3 -c 'import sys; print(1 if sys.version_info >= (3,10) else 0)' 2>/dev/null || echo 0)"
    PY_VER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo '?')"
    if [ "$PY_OK" != "1" ]; then
        echo -e "${RED}[ERR] 需要 Python 3.10 或更高，当前 ${PY_VER}${NC}"
        echo -e "  代码使用 3.10 的类型注解语法（str | None），低版本会直接语法错误。"
        echo -e "  Ubuntu/Debian: ${BOLD}apt install -y python3${NC}（或升级系统）"
        echo -e "  CentOS/RHEL:   ${BOLD}dnf install -y python3.11${NC}"
        exit 1
    fi
    echo -e "  ${GREEN}[OK] Python ${PY_VER}${NC}"
else
    echo -e "${RED}[ERR] 未找到 python3，请先安装：apt install -y python3${NC}"
    exit 1
fi

# screen：irds 的后台会话 + detach/续接依赖它。
# 另外它是 attach 门控的硬依赖 —— 面板与结果下载只在 attach 时开放，
# 没有 screen 就退化为前台直跑（前台等价 attached，服务照常可用）。
if ! command -v screen &>/dev/null; then
    echo -e "  ${YELLOW}[WARN] screen 未安装，自动安装...${NC}"
    # 与 masscan 对称：set -e 下安装失败不应中断脚本
    if command -v apt &>/dev/null; then
        $SUDO apt install -y -qq screen 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        $SUDO dnf install -y -q screen 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        $SUDO yum install -y -q screen 2>/dev/null || true
    elif command -v apk &>/dev/null; then
        $SUDO apk add --no-progress screen 2>/dev/null || true
    fi
    if ! command -v screen &>/dev/null; then
        echo -e "${YELLOW}  [WARN] screen 安装失败（权限不足或源不可用），irds 将退化为前台直跑${NC}"
    fi
fi
if command -v screen &>/dev/null; then
    echo -e "  ${GREEN}[OK] screen: $(screen --version 2>&1 | head -1)${NC}"
else
    echo -e "  ${YELLOW}[WARN] screen 不可用，irds 将退化为前台直跑（无法 detach/续接）${NC}"
fi

# psutil（可选）：仅非 Linux 才需要；Linux 直接读 /proc，装不上无影响
# fuser（psmisc）/ lsof：端口释放与残留句柄诊断，缺失时代码有兜底
for _opt in fuser lsof; do
    if ! command -v "$_opt" &>/dev/null; then
        case "$_opt" in
            fuser) _pkg="psmisc" ;;
            lsof)  _pkg="lsof" ;;
        esac
        if command -v apt &>/dev/null; then
            $SUDO apt install -y -qq "$_pkg" 2>/dev/null || true
        elif command -v dnf &>/dev/null; then
            $SUDO dnf install -y -q "$_pkg" 2>/dev/null || true
        elif command -v yum &>/dev/null; then
            $SUDO yum install -y -q "$_pkg" 2>/dev/null || true
        elif command -v apk &>/dev/null; then
            $SUDO apk add --no-progress "$_pkg" 2>/dev/null || true
        fi
    fi
done

# cf-scanner
CF_SCANNER="${INSTALL_DIR}/src/cf-scanner"
if [ -f "$CF_SCANNER" ]; then
    chmod +x "$CF_SCANNER"
    echo -e "  ${GREEN}[OK] cf-scanner: 就绪${NC}"
else
    echo -e "  ${YELLOW}[WARN] cf-scanner 未找到，尝试编译...${NC}"
    if command -v go &>/dev/null && [ -d "${INSTALL_DIR}/src/cf-scanner-src" ]; then
        cd "${INSTALL_DIR}/src/cf-scanner-src"
        go build -o "$CF_SCANNER" . && {
            chmod +x "$CF_SCANNER"
            echo -e "  ${GREEN}[OK] cf-scanner: 编译成功${NC}"
        } || {
            echo -e "  ${YELLOW}  [WARN] 编译失败${NC}"
        }
    else
        # 原 elif [ -f "$CF_SCANNER" ] 分支是死代码（外层已确认文件不存在，且该分支不会创建它），已删除
        echo -e "  ${YELLOW}  [WARN] cf-scanner 未找到，scan 会跳过 verify 步骤${NC}"
    fi
fi
echo ""

# ---- 创建 asnip 命令（总是覆盖到最新）----
mkdir -p "${INSTALL_DIR}/bin"
{
  echo '#!/usr/bin/env bash'
  echo 'self="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"'
  echo 'DIR="$(cd "$(dirname "$self")/../src" && pwd)"'
  echo 'cd "$DIR"'
  echo 'exec python3 asnip.py "$@"'
} > "${INSTALL_DIR}/bin/asnip"
chmod +x "${INSTALL_DIR}/bin/asnip"

{
  echo '#!/usr/bin/env bash'
  echo 'self="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"'
  echo 'DIR="$(cd "$(dirname "$self")/../src" && pwd)"'
  echo 'cd "$DIR"'
  echo 'exec python3 asnip.py scan "$@"'
} > "${INSTALL_DIR}/bin/ips"
chmod +x "${INSTALL_DIR}/bin/ips"

# 清理可能残留的旧 broken symlink
rm -f /usr/local/bin/asnip /usr/local/bin/ips /usr/local/bin/irds /usr/local/bin/irds-result 2>/dev/null || true

# 装到系统 PATH 目录，立即可用，不依赖 bashrc
BIN_DIR="${INSTALL_DIR}/bin"
mkdir -p "$BIN_DIR"

cat > "$BIN_DIR/irds" << 'SCRIPT'
#!/usr/bin/env bash
self="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
DIR="$(cd "$(dirname "$self")/../src" && pwd)"

# ===== 版本核对（本地已安装 vs GitHub 远端）=====
_asnip_version() {
    local VF="$DIR/.version"
    local LOCAL_SHA="unknown" INSTALLED="-" SRC="-"
    if [ -f "$VF" ]; then
        LOCAL_SHA="$(grep '^commit=' "$VF" | cut -d= -f2-)"
        INSTALLED="$(grep '^installed_at=' "$VF" | cut -d= -f2-)"
        SRC="$(grep '^source=' "$VF" | cut -d= -f2-)"
    fi
    echo ""
    echo "  ASNIPtest 版本信息"
    echo "  ------------------------------------------------"
    echo "  已安装 commit : ${LOCAL_SHA}"
    echo "  安装时间      : ${INSTALLED}"
    echo "  来源          : ${SRC}"

    local REMOTE_SHA=""
    if command -v git >/dev/null 2>&1; then
        REMOTE_SHA="$(git ls-remote https://github.com/take2be/ASNIPtest.git \
                        refs/heads/master 2>/dev/null | cut -f1 | head -1)"
    fi
    if [ -z "$REMOTE_SHA" ] && command -v curl >/dev/null 2>&1; then
        REMOTE_SHA="$(curl -fsSL --connect-timeout 15 --max-time 30 \
                        'https://api.github.com/repos/take2be/ASNIPtest/commits/master' 2>/dev/null \
                        | grep -oE '"sha"[[:space:]]*:[[:space:]]*"[a-f0-9]{40}"' | head -1 \
                        | grep -oE '[a-f0-9]{40}')"
    fi
    if [ -z "$REMOTE_SHA" ]; then
        echo "  远端 commit   : (查询失败，检查网络/代理)"
        echo "  ------------------------------------------------"
        return 0
    fi
    echo "  远端 commit   : ${REMOTE_SHA}"
    echo "  ------------------------------------------------"
    if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
        echo "  [OK] 已是最新版本"
    else
        echo "  [WARN] 本地不是最新版本！"
        echo "         重新安装以更新:"
        echo "         bash <(curl -fsSL https://raw.githubusercontent.com/take2be/ASNIPtest/master/install.sh)"
    fi
    echo ""
}

# ===== 面板说明（token 是一次性的，attach 时才打印）=====
_asnip_panel() {
    echo ""
    echo "  进度面板与结果下载只在 attach 进扫描会话时开放。"
    echo ""
    echo "  用法:"
    echo "    irds -ls          查看有哪些会话"
    echo "    irds <ASN>        attach 进对应会话（已在跑则直接接入）"
    echo ""
    echo "  attach 后终端会打印本次专用的访问链接（自带一次性 token）。"
    echo "  detach（Ctrl+A D）后端口立即关闭，重新 attach 会换新链接。"
    echo "  彻底结束: 会话内 Ctrl+C 或 Ctrl+A K Y"
    echo ""
}

# ===== 管理子命令（不启动扫描，直接处理）=====
case "$1" in
    -version|--version|-v)
        _asnip_version
        exit 0 ;;
    -panel|--panel)
        _asnip_panel
        exit 0 ;;
    -ls|-list)
        echo "当前 ASNIPtest screen 会话:"
        screen -ls 2>/dev/null | grep -E '\.asnip' || echo "  (无)"
        exit 0 ;;
    -stop)
        # 停止指定 ASN 的会话（含单 ASN 和多 ASN 的 multi 复合会话）：
        # irds -stop <asn>   （如 irds -stop 36002）
        TGT="$2"
        if [ -z "$TGT" ]; then
            echo "用法: irds -stop <ASN>   （如 irds -stop 36002）"
            exit 1
        fi
        # 找出所有以 asnip-<ASN> 开头的会话（含 -multi），逐个停止
        STOPS=$(screen -ls 2>/dev/null | grep -E "\\.asnip-${TGT}(-multi)?[[:space:]]" | grep -oE "[0-9]+\\.asnip[-a-zA-Z0-9]+" | sort -u)
        if [ -n "$STOPS" ]; then
            echo "$STOPS" | while read -r s; do
                screen -S "$s" -X quit 2>/dev/null && echo "[OK] 已停止 $s"
            done
            echo "（如仍有未清会话，可用 irds -ls 查看）"
        else
            echo "[WARN] 未找到 asnip-${TGT} 或 asnip-${TGT}-multi 会话（用 irds -ls 查看）"
        fi
        exit 0 ;;
    -stop-all)
        echo "停止所有 ASNIPtest screen 会话..."
        screen -ls 2>/dev/null | grep -E '\.asnip' | awk '{print $1}' | while read -r s; do
            screen -S "$s" -X quit 2>/dev/null
        done
        screen -wipe 2>/dev/null
        echo "[OK] 已停止全部 asnip 会话（如需彻底清除请用 uninstall）"
        exit 0 ;;
esac
# ===== 管理子命令结束 =====

# ===== 无参数交互菜单（与管理子命令并行）=====
# 直接输入 irds（不带参数）→ 弹管理菜单；选择"开始新扫描"才进入扫描流程
if [ "$#" -eq 0 ]; then
    echo ""
    echo "================================================"
    echo "  ASNIPtest 会话管理"
    echo "================================================"
    echo "  1) 列出当前会话"
    echo "  2) 停止某个 ASN 的会话"
    echo "  3) 停止全部会话"
    echo "  4) 开始新扫描"
    echo "  5) 查看版本（与 GitHub 最新版核对）"
    echo "  6) 面板与下载的使用说明"
    echo "  0) 退出"
    echo "------------------------------------------------"
    printf "  请选择 [0-6]: "
    read -r CHOICE
    case "$CHOICE" in
        1)
            # 列出会话并编号，输入编号即 attach 进入该 screen
            mapfile -t SESS <<< "$(screen -ls 2>/dev/null | grep -E '\.asnip' | grep -oE '[0-9]+\.asnip[-a-zA-Z0-9]+' | sort -u)"
            if [ "${#SESS[@]}" -eq 0 ] || [ -z "${SESS[0]}" ]; then
                echo "  (无 asnip 会话)"
                exit 0
            fi
            echo ""
            for i in "${!SESS[@]}"; do
                printf "  %d) %s\n" "$((i+1))" "${SESS[$i]}"
            done
            printf "  请输入编号进入会话 (0 返回): "
            read -r IDX
            if [ "$IDX" = "0" ] || [ -z "$IDX" ]; then exit 0; fi
            if [[ "$IDX" =~ ^[0-9]+$ ]] && [ "$IDX" -ge 1 ] && [ "$IDX" -le "${#SESS[@]}" ]; then
                TGT="${SESS[$((IDX-1))]}"
                echo "  接入 ${TGT} ..."
                exec screen -r "$TGT"
            else
                echo "  [WARN] 无效编号"
            fi
            exit 0 ;;
        2)
            # 列出会话并编号，输入编号即停止该会话
            mapfile -t SESS <<< "$(screen -ls 2>/dev/null | grep -E '\.asnip' | grep -oE '[0-9]+\.asnip[-a-zA-Z0-9]+' | sort -u)"
            if [ "${#SESS[@]}" -eq 0 ] || [ -z "${SESS[0]}" ]; then
                echo "  (无 asnip 会话)"
                exit 0
            fi
            echo ""
            for i in "${!SESS[@]}"; do
                printf "  %d) %s\n" "$((i+1))" "${SESS[$i]}"
            done
            printf "  请输入编号停止会话 (0 返回): "
            read -r IDX
            if [ "$IDX" = "0" ] || [ -z "$IDX" ]; then exit 0; fi
            if [[ "$IDX" =~ ^[0-9]+$ ]] && [ "$IDX" -ge 1 ] && [ "$IDX" -le "${#SESS[@]}" ]; then
                TGT="${SESS[$((IDX-1))]}"
                screen -S "$TGT" -X quit 2>/dev/null && echo "  [OK] 已停止 $TGT"
            else
                echo "  [WARN] 无效编号"
            fi
            exit 0 ;;
        3)
            echo "  停止所有 ASNIPtest screen 会话..."
            screen -ls 2>/dev/null | grep -E '\.asnip' | awk '{print $1}' | while read -r s; do
                screen -S "$s" -X quit 2>/dev/null
            done
            screen -wipe 2>/dev/null
            echo "  [OK] 已停止全部"
            exit 0 ;;
        4)
            # 开始新扫描：继续走下面正常流程（不退出）
            echo "  开始新扫描..."
            ;;
        5)
            _asnip_version
            exit 0 ;;
        6)
            _asnip_panel
            exit 0 ;;
        0|"")
            exit 0 ;;
        *)
            echo "  无效选择，退出"
            exit 1 ;;
    esac
fi
# ===== 无参数交互菜单结束 =====

# 解析 ASN 参数：跳过带值选项（--ports/--rate/--top/--port/--progress-port）及其值，
# 避免选项值（如 443）被误当成 ASN。判断单/复合，取第一个 ASN 作为会话名。
FIRST_ASN=""
ASN_COUNT=0
IS_MULTI=false
SKIP_NEXT=false
for a in "$@"; do
    if [ "$SKIP_NEXT" = true ]; then
        SKIP_NEXT=false           # 跳过选项的值
        continue
    fi
    case "$a" in
        --ports|--rate|--top|--port|--progress-port)
            SKIP_NEXT=true ;;     # 带值选项，跳过它和它的下一个值
        --*) continue ;;          # 布尔选项（--force --json --no-deps --daemon）直接跳过
        *)
            ASN_COUNT=$((ASN_COUNT+1))
            if [[ "$a" == *,* ]]; then
                IS_MULTI=true      # 逗号分隔多个 ASN → 复合任务
            fi
            if [ -z "$FIRST_ASN" ]; then
                FIRST_ASN="${a%%,*}"
            fi
            ;;
    esac
done
# 多个位置参数（如 irds 13335 36002）也是复合任务
if [ "$ASN_COUNT" -gt 1 ]; then
    IS_MULTI=true
fi

# SESSION 名：
#   复合(多ASN) → asnip-<第一个>--multi   便于识别是复合任务
#   单个ASN     → asnip-<ASN>
#   无参数      → asnip（兼容）
if [[ "$FIRST_ASN" =~ ^[0-9]+$ ]] && [ "$IS_MULTI" = true ]; then
    SESSION="asnip-${FIRST_ASN}-multi"
elif [[ "$FIRST_ASN" =~ ^[0-9]+$ ]]; then
    SESSION="asnip-${FIRST_ASN}"
else
    SESSION="asnip"
fi

# 已经身处 screen 会话内（比如用户手动 screen -r 进来的），直接跑，不要嵌套 screen
if [ -n "$STY" ]; then
    cd "$DIR"
    exec python3 asnip.py scan "$@"
fi

# 没装 screen 就退化为前台直跑
if ! command -v screen &>/dev/null; then
    echo "[WARN] 未检测到 screen，直接前台运行（无法 detach/续接，建议先安装 screen）"
    cd "$DIR"
    exec python3 asnip.py scan "$@"
fi

# 已有同名会话在跑 → 直接接回去（精准 attach 到对应 ASN 的会话）
if screen -ls 2>/dev/null | grep -qE "\.${SESSION}[[:space:]]"; then
    echo "检测到已有 ${SESSION} 会话，正在接入进度界面..."
    exec screen -r "$SESSION"
fi

# 否则新建一个后台 detached 会话去真正跑任务，再 attach 进去
ARGS=""
for a in "$@"; do
    ARGS="$ARGS $(printf '%q' "$a")"
done
echo "后台启动 ${SESSION} 会话..."
screen -dmS "$SESSION" bash -c "cd '$DIR' && python3 asnip.py scan $ARGS; echo; echo '[任务已结束，按回车关闭窗口]'; read"
sleep 1
exec screen -r "$SESSION"
SCRIPT
chmod +x "$BIN_DIR/irds"
# 安装自检：验证生成的 irds 语法（防止 heredoc 在传输/编码中被破坏）
if ! bash -n "$BIN_DIR/irds" 2>/dev/null; then
    echo -e "${RED}[ERR] 生成的 irds 语法检查失败，安装中止${NC}"
    echo -e "  请用 ${BOLD}LANG=C.UTF-8 LC_ALL=C.UTF-8${NC} 重新运行安装脚本"
    exit 1
fi

cat > "$BIN_DIR/irds-result" << 'SCRIPT'
#!/usr/bin/env bash
rpt=""
if [ -d "${HOME}/.asnip/src" ]; then
    # 结果文件命名格式为 output_{ASN}_{时间戳}.csv
    rpt=$(find "${HOME}/.asnip/src" -maxdepth 1 -name "output_*.csv" -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
fi
if [ -z "$rpt" ] || [ ! -f "$rpt" ]; then
    echo "尚未找到 output_*.csv 结果文件"
    exit 1
fi
echo "报告: $rpt"
python3 - "$rpt" << 'PY'
import csv, sys
p = sys.argv[1]
rows = []
with open(p, newline='', encoding='utf-8', errors='replace') as f:
    for r in csv.DictReader(f):
        rows.append(r)
if not rows:
    print("空报告")
    sys.exit(0)

valid = [r for r in rows if r.get("网络延迟(ms)") not in ("-", "")]
print(f"总行: {len(rows)}，有效: {len(valid)}")
if valid:
    def _lat(r):
        try:
            return float(r.get("网络延迟(ms)", 99999) or 99999)
        except (ValueError, TypeError):
            return 99999
    valid_sorted = sorted(valid, key=_lat)
    print("Top 10 可用:")
    print("%-18s %-10s %8s %6s %s" % ("IP:PORT", "地区", "延迟ms", "国旗", "ASN组织"))
    for r in valid_sorted[:10]:
        ip = r.get("IP地址", "?")
        port = r.get("端口号", "")
        ip_port = f"{ip}:{port}" if port else ip
        print("%-18s %-10s %8sms %6s %s" % (
            ip_port,
            (r.get("IP位置", "-") or "-")[:10],
            r.get("网络延迟(ms)", "-"),
            (r.get("国旗", "") or ""),
            (r.get("ASN组织", "-") or "-")[:22],
        ))
PY
SCRIPT
chmod +x "$BIN_DIR/irds-result"

# irds-http：临时拉起 HTTP 服务查看最新结果（serve 走 asnip.py serve，不能用 ips）
cat > "$BIN_DIR/irds-http" << 'SCRIPT'
#!/bin/bash
# 解析 symlink 到真实安装目录，再定位 src
self="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
bin="$(dirname "$self")"
DIR="$(cd "$bin/../src" && pwd)"
cd "$DIR" && exec python3 asnip.py serve "$@"
SCRIPT
chmod +x "$BIN_DIR/irds-http"

# irds-progress：单独拉起网页进度面板（默认 8082），带一次性访问令牌
# 令牌逻辑统一在 asnip.py progress 里（环境变量注入，不进命令行）
cat > "$BIN_DIR/irds-progress" << 'SCRIPT'
#!/bin/bash
# 解析 symlink 到真实安装目录，再定位 src（兼容 /usr/local/bin 等 system 链接）
self="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
bin="$(dirname "$self")"
DIR="$(cd "$bin/../src" && pwd)"
cd "$DIR" && exec python3 asnip.py progress "$@"
SCRIPT
chmod +x "$BIN_DIR/irds-progress"

echo -e " ${GREEN}[OK] irds / irds-result / irds-http / irds-progress / ips 已注册到 $BIN_DIR/${NC}"

# 创建 system symlink，立即可用，不依赖 bashrc
SYMLINK_OK=true
ln -sf "$BIN_DIR/irds" /usr/local/bin/irds 2>/dev/null || SYMLINK_OK=false
ln -sf "$BIN_DIR/irds-result" /usr/local/bin/irds-result 2>/dev/null || SYMLINK_OK=false
ln -sf "$BIN_DIR/irds-http" /usr/local/bin/irds-http 2>/dev/null || SYMLINK_OK=false
ln -sf "$BIN_DIR/irds-progress" /usr/local/bin/irds-progress 2>/dev/null || SYMLINK_OK=false
ln -sf "$BIN_DIR/ips" /usr/local/bin/ips 2>/dev/null || SYMLINK_OK=false
# 原写法用 || true 直接吞掉失败，用户会看到"安装完成"但命令实际不在 PATH 里；这里检测并提示
if [ "$SYMLINK_OK" = false ]; then
    echo -e "${YELLOW}[WARN] 无权限写入 /usr/local/bin，命令未注册到系统 PATH${NC}"
    echo -e "  请手动执行: ${BOLD}echo 'export PATH=\"\$HOME/.asnip/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc${NC}"
fi

# 记录项目安装根目录，供 uninstall.sh 精准删除（避免残留项目根）
# SCRIPT_SRC 是 install.sh 所在/复制来源的目录，即为项目根
if [ -n "${SCRIPT_SRC:-}" ] && [ -d "${SCRIPT_SRC}" ]; then
    echo "${SCRIPT_SRC}" > "${INSTALL_DIR}/.install_root" 2>/dev/null || true
fi

# ---- 完成 ----
echo -e "${GREEN}${BOLD}========================================${NC}"
echo -e "${GREEN}${BOLD}  安装完成！${NC}"
echo -e "${GREEN}${BOLD}========================================${NC}"
echo ""
echo -e "  安装目录: ${INSTALL_DIR}"
if [ -f "${INSTALL_DIR}/src/.version" ]; then
    _V="$(grep '^commit=' "${INSTALL_DIR}/src/.version" | cut -d= -f2-)"
    echo -e "  已装版本: ${BOLD}${_V}${NC}"
fi
echo ""
echo -e "  ${BOLD}安全说明：${NC}"
echo -e "    进度面板与结果下载${BOLD}只在 attach 进扫描会话时开放${NC}，"
echo -e "    detach 后端口立即关闭。每次 attach 生成新的一次性访问令牌，"
echo -e "    链接直接打印在你的终端里（不落盘、不进日志）。"
echo ""
echo -e "  常用命令："
echo -e "    ${BOLD}irds <ASN>${NC}         启动扫描 / 接回已有会话（attach 后显示面板链接）"
echo -e "    ${BOLD}irds -version${NC}      查看已装版本并与 GitHub 最新版核对"
echo -e "    ${BOLD}irds -panel${NC}        面板与下载的使用说明"
echo -e "    ${BOLD}irds-result${NC}       查看最近一次扫描结果（可用 IP 汇总）"
echo -e "    ${BOLD}screen -r asnip${NC}    查看当前扫描进度"
echo -e "    ${BOLD}Ctrl+A D${NC}           detach 返回主 shell，任务继续跑（端口随之关闭）"
echo ""
