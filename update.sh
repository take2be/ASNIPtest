#!/usr/bin/env bash
# ASNIPtest 热更新脚本
# 用法: bash update.sh   （在任意目录执行）
# 特点: 不中断正在运行的扫描, 不动 scan_data 数据, 只覆盖代码文件, 自动重启面板
set -uo pipefail

INSTALL_DIR="${HOME}/.asnip"
SRC_DIR="${INSTALL_DIR}/src"
TMP_DIR="/tmp/asnip-update-$$"
TARBALL="${TMP_DIR}/master.tar.gz"

echo "[*] ASNIPtest 热更新..."
# 先切到稳定目录（修复 cwd 指向已删目录时 pip/python 崩溃）
cd "$HOME" 2>/dev/null || cd / 2>/dev/null || true

# 1. 定位安装目录
if [ ! -d "$SRC_DIR" ]; then
    # 兼容旧路径: /root/.asnip/src 不存在则找已安装位置
    for c in /usr/local/bin/irds-progress /root/.asnip/bin/irds-progress; do
        if [ -f "$c" ]; then
            SRC_DIR="$(cd "$(dirname "$(readlink -f "$c")")/../src" && pwd)"
            break
        fi
    done
fi
if [ ! -f "$SRC_DIR/progress_server.py" ]; then
    echo "[ERR] 未找到安装目录 ($SRC_DIR)，请确认已执行过 install.sh"
    exit 1
fi
echo "  安装目录: $SRC_DIR"

# 2. 下载最新代码 (优先走代理)
# 按 commit SHA 下载：按分支名的归档缓存键就是分支名，force-push 后
# CDN 可能继续返回旧内容 → 更新出来不是最新版。按 SHA 的归档不可变。
mkdir -p "$TMP_DIR"
PROXY_ADDR=""
if echo "${http_proxy:-}${https_proxy:-}" | grep -qiE "socks|10808"; then
    PROXY_ADDR="$(echo "${http_proxy:-$https_proxy}" | sed 's|.*://||')"
fi
_dl() {   # _dl <url> <out>
    if [ -n "$PROXY_ADDR" ]; then
        curl -fsSL --retry 3 --retry-delay 3 --connect-timeout 15 \
          --socks5-hostname "$PROXY_ADDR" -o "$2" "$1" 2>/dev/null || \
        curl -fsSL --retry 3 --retry-delay 3 --connect-timeout 15 -o "$2" "$1"
    else
        curl -fsSL --retry 3 --retry-delay 3 --connect-timeout 15 -o "$2" "$1"
    fi
}

REMOTE_SHA=""
if command -v git >/dev/null 2>&1; then
    REMOTE_SHA="$(git ls-remote https://github.com/take2be/ASNIPtest.git \
                    refs/heads/master 2>/dev/null | cut -f1 | head -1)"
fi
if [ -z "$REMOTE_SHA" ]; then
    _dl "https://api.github.com/repos/take2be/ASNIPtest/commits/master" "$TMP_DIR/api.json" || true
    REMOTE_SHA="$(grep -oE '"sha"[[:space:]]*:[[:space:]]*"[a-f0-9]{40}"' "$TMP_DIR/api.json" 2>/dev/null \
                  | head -1 | grep -oE '[a-f0-9]{40}')"
fi

# 已是最新则不必重下（避免无谓下载 4MB）
LOCAL_SHA="$(grep '^commit=' "$SRC_DIR/.version" 2>/dev/null | cut -d= -f2-)"
if [ -n "$REMOTE_SHA" ] && [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
    echo "  已是最新版本 (${REMOTE_SHA:0:7})，仅重启面板"
    SKIP_DOWNLOAD=true
else
    SKIP_DOWNLOAD=false
fi

if [ "$SKIP_DOWNLOAD" = false ]; then
    if [ -n "$REMOTE_SHA" ]; then
        URL="https://github.com/take2be/ASNIPtest/archive/${REMOTE_SHA}.tar.gz"
        echo "  目标版本: ${REMOTE_SHA:0:7}"
    else
        URL="https://github.com/take2be/ASNIPtest/archive/refs/heads/master.tar.gz"
        echo "  [WARN] 无法解析 commit SHA，退回分支归档（可能命中 CDN 缓存）"
    fi
    _dl "$URL" "$TARBALL"
    if [ ! -s "$TARBALL" ]; then
        echo "[ERR] 下载失败，请检查网络后重试"
        rm -rf "$TMP_DIR"
        exit 1
    fi

    # 3. 解压并校验（目录名随 SHA/分支变化，用通配定位）
    tar xzf "$TARBALL" -C "$TMP_DIR"
    NEW_DIR="$(find "$TMP_DIR" -maxdepth 1 -type d -name 'ASNIPtest-*' | head -1)"
    if [ -z "$NEW_DIR" ] || [ ! -f "$NEW_DIR/progress_server.py" ]; then
        echo "[ERR] 解压校验失败（缺少 progress_server.py）"
        rm -rf "$TMP_DIR"
        exit 1
    fi

    # 4. 覆盖代码文件（保留 scan_data/cache/output 等运行数据）
    echo "  覆盖代码文件..."
    cd "$SRC_DIR"
    for item in "$NEW_DIR"/*; do
        base="$(basename "$item")"
        case "$base" in
            scan_data|cache|work|output_*|*.csv|*.json) continue ;;  # 运行数据不动
        esac
        rm -rf "$SRC_DIR/$base"
        cp -r "$item" "$SRC_DIR/$base"
    done
    # 记录版本，供 irds -version 核对
    {
        echo "commit=${REMOTE_SHA:-unknown}"
        echo "source=$URL"
        echo "installed_at=$(date '+%Y-%m-%d %H:%M:%S %z')"
    } > "$SRC_DIR/.version"
fi

# 5. 语法自检（防止坏代码导致扫描崩溃）
cd "$SRC_DIR" || { echo "[ERR] 无法进入 $SRC_DIR"; rm -rf "$TMP_DIR"; exit 1; }
if ! python3 -c "import ast; [ast.parse(open(f, encoding='utf-8').read()) for f in ['progress_server.py','asnip.py','attach_guard.py','pipeline/orchestrator.py','pipeline/stage2_masscan.py']]"; then
    echo "[ERR] 新代码语法检查失败，已回滚？请手动检查 $SRC_DIR"
    rm -rf "$TMP_DIR"
    exit 1
fi

# 6. 清理裸奔的面板进程（不影响正在运行的扫描进程）
# 面板不再常驻：它只在 attach 进 screen 会话时启动（一次性 token），
# detach 立即关闭端口。这里只杀掉旧版留下的无鉴权常驻面板。
if pgrep -f "progress_server\.py" >/dev/null 2>&1; then
    echo "  清理旧版常驻面板进程（面板改为 attach 时才开放）..."
    pkill -f "progress_server\.py" 2>/dev/null || true
    sleep 1
fi
if ! command -v python3 &>/dev/null; then
    echo "[ERR] python3 不可用"
    rm -rf "$TMP_DIR"
    exit 1
fi
echo "  [OK] 代码已更新；attach 进扫描会话即可看到面板与下载链接"

# 7. 清理
rm -rf "$TMP_DIR"
echo ""
echo "[OK] 更新完成！版本 ${REMOTE_SHA:-unknown}"
echo "  - 正在运行的扫描不受影响（代码已加载进内存）"
echo "  - 面板与结果下载只在 attach 进扫描会话时开放，detach 即关端口"
echo "  - 下次扫描(irds <ASN>) 将使用全部新功能"
echo "  - 核对版本: irds -version"
