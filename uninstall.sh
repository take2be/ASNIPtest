#!/usr/bin/env bash
# ASNIPtest 一键卸载脚本
set -uo pipefail

INSTALL_DIR="${HOME}/.asnip"

echo " ASNIPtest 卸载中..."
echo ""

# ===== 第一步：杀进程 =====
# 必须先杀进程，否则 daemon wrapper 会不断重拉
# 策略：先删命令入口（让 respawn 失败），再杀所有相关进程
echo "  清理 ASNIPtest 相关进程..."

# 先删命令入口，让正在运行的 wrapper 下次重拉时因找不到命令而退出
rm -f /usr/local/bin/irds 2>/dev/null || true
rm -f /usr/local/bin/irds-result irds-http 2>/dev/null || true
rm -f /usr/local/bin/irds-progress 2>/dev/null || true
rm -f /usr/local/bin/irds-http 2>/dev/null || true
rm -f /usr/local/bin/ips 2>/dev/null || true
rm -f /usr/local/bin/asnip 2>/dev/null || true
rm -f "${HOME}/.local/bin/irds" "${HOME}/.local/bin/irds-result" "${HOME}/.local/bin/irds-http" 2>/dev/null || true
rm -f "${HOME}/bin/asnip" 2>/dev/null || true
rm -f "${HOME}/.asnip/bin/irds" "${HOME}/.asnip/bin/irds-result" "${HOME}/.asnip/bin/irds-http" "${HOME}/.asnip/bin/irds-progress" "${HOME}/.asnip/bin/ips" "${HOME}/.asnip/bin/asnip" 2>/dev/null || true

# 杀 progress_server 进程（扫描结束没来得及停时残留）
pkill -9 -f "progress_server\.py" 2>/dev/null || true

# 杀 python asnip 进程（仅匹配 asnip.py 脚本，不含其他进程）
pkill -9 -f "^python3.*asnip\.py" 2>/dev/null || true
# 杀 masscan / cf-scanner 子进程：父进程被 OOM kill 后它们会变成孤儿继续跑、
# 继续写盘，并持有已删除文件的句柄——不杀掉磁盘空间不会释放、内存也降不下来
pkill -9 -x masscan 2>/dev/null || true
pkill -9 -f "masscan .*-oJ" 2>/dev/null || true
pkill -9 -x cf-scanner 2>/dev/null || true
pkill -9 -f "cf-scanner" 2>/dev/null || true
# 杀 ips 包装器脚本（daemon 循环，仅匹配 ips 命令）
pkill -9 -f "^/.*ips --daemon" 2>/dev/null || true
pkill -9 -f "^/.*ips\" .* --daemon" 2>/dev/null || true
# 杀 daemon 死循环 wrapper（trap '' HUP + while true，仅匹配 ips/asnip 相关）
pkill -9 -f "trap.*HUP.*while.*true.*ips" 2>/dev/null || true
pkill -9 -f "trap.*HUP.*while.*true.*asnip" 2>/dev/null || true
# 杀 while 循环检测 report.csv 的 daemon wrapper
pkill -9 -f "while.*true.*report\.csv.*sleep.*10" 2>/dev/null || true
# 注意：不盲目 pkill -f "asnip" 或 "report.csv"——太宽泛会杀到 SSH 自身
sleep 1
echo "  [OK] 进程已清理"

# 清理残留的 screen/tmux session（先杀，避免 screen 里有进程）
if command -v screen >/dev/null 2>&1; then
    screen -ls 2>/dev/null | grep -oE '[0-9]+\.asnip' | while read -r s; do
        screen -X -S "$s" quit 2>/dev/null || true
    done
    # 也杀用户建的 asnip-install 等 screen
    screen -ls 2>/dev/null | grep -oE '[0-9]+\.asnip[-a-zA-Z]*' | while read -r s; do
        screen -X -S "$s" quit 2>/dev/null || true
    done
    # 清理僵尸（Dead）会话：screen -X quit 对 Dead 无效，必须 screen -wipe
    screen -wipe 2>/dev/null || true
fi
if command -v tmux >/dev/null 2>&1; then
    tmux has-session -t asnip 2>/dev/null && tmux kill-session -t asnip 2>/dev/null || true
fi

echo ""

# 删系统 PATH 下的命令入口（补刀，确保已删）
rm -f /usr/local/bin/irds 2>/dev/null || true
rm -f /usr/local/bin/irds-result irds-http 2>/dev/null || true
rm -f /usr/local/bin/irds-progress 2>/dev/null || true
rm -f /usr/local/bin/irds-http 2>/dev/null || true
rm -f /usr/local/bin/ips 2>/dev/null || true
rm -f /usr/local/bin/asnip 2>/dev/null || true
rm -f "${HOME}/.local/bin/irds" "${HOME}/.local/bin/irds-result" "${HOME}/.local/bin/irds-http" 2>/dev/null || true
rm -f "${HOME}/bin/asnip" 2>/dev/null || true
rm -f "${HOME}/.asnip/bin/irds" "${HOME}/.asnip/bin/irds-result" "${HOME}/.asnip/bin/irds-http" "${HOME}/.asnip/bin/irds-progress" "${HOME}/.asnip/bin/ips" "${HOME}/.asnip/bin/asnip" 2>/dev/null || true

# 删安装/更新过程产生的临时文件（覆盖 asnip-前缀的所有变体，含无横杠的）
rm -rf /tmp/asnip-dl 2>/dev/null || true
rm -rf /tmp/asnip-update-* 2>/dev/null || true
rm -f /tmp/asnip-install.sh 2>/dev/null || true
rm -f /tmp/asnip-*.log /tmp/asnip-*.txt 2>/dev/null || true
rm -f /tmp/asnip*.log /tmp/asnip*.txt 2>/dev/null || true
# update.sh 一键热更会把自己下到 /tmp
rm -f /tmp/update.sh 2>/dev/null || true
# GeoLite2 下载/解压残留：tar 解出的是 GeoLite2-City_YYYYMMDD/ 目录
# （每个约 80MB，install.sh 只删了 .tar.gz，目录一直留着）
rm -rf /tmp/GeoLite2-City_* /tmp/GeoLite2-ASN_* 2>/dev/null || true
rm -f /tmp/GeoLite2-City.tar.gz /tmp/GeoLite2-ASN.tar.gz 2>/dev/null || true
# pip 引导脚本（install.sh 在没有 pip 时会下载它）
rm -f /tmp/get-pip.py 2>/dev/null || true

# 删项目安装根目录（关键：install.sh 把仓库 clone/copy 到某目录，必须连根删）
# 优先读 install.sh 写入的标记文件
ROOT_FROM_MARKER=""
if [ -f "${INSTALL_DIR}/.install_root" ]; then
    ROOT_FROM_MARKER="$(cat "${INSTALL_DIR}/.install_root" 2>/dev/null | head -1)"
fi

# 候选项目根：标记指向的目录 + 常见位置 + 项目自身生成的带时间戳备份目录
# 仅当目录确实像本项目（含 asnip.py 与 pipeline/）才删，避免误删用户文件
CANDIDATES=""
[ -n "${ROOT_FROM_MARKER}" ] && CANDIDATES="${CANDIDATES} ${ROOT_FROM_MARKER}"
CANDIDATES="${CANDIDATES} ${HOME}/ASNIPtest ${HOME}/asnip ${HOME}/projects/ASNIPtest-optimized /root/ASNIPtest /opt/asnip /opt/ASNIPtest /usr/local/asnip /usr/local/ASNIPtest"

# 项目自身可能生成 ASNIPtest-backup-<时间戳> 备份目录，一并清除
for bk in "${HOME}"/ASNIPtest-backup-* /root/ASNIPtest-backup-* /opt/ASNIPtest-backup-*; do
    [ -d "$bk" ] && CANDIDATES="${CANDIDATES} $bk"
done

for d in ${CANDIDATES}; do
    [ -z "$d" ] && continue
    # 校验：必须是目录、且含项目特征文件，才认定是项目根
    if [ -d "$d" ] && [ -f "$d/asnip.py" ] && [ -d "$d/pipeline" ]; then
        echo "  删除项目根: $d"
        rm -rf "$d" 2>/dev/null || true
    fi
done


# 删安装目录全部内容（含 bin/ 下的命令本体、src、scan_data、cache、config）
rm -rf "$INSTALL_DIR" 2>/dev/null || true

# 二次确认：若仍有进程持有已删文件的句柄，磁盘空间不会释放。
# 这里再补一刀（前面已 pkill，此处兜底 masscan/cf-scanner 的慢退出）。
pkill -9 -x masscan 2>/dev/null || true
pkill -9 -x cf-scanner 2>/dev/null || true
sleep 1

# 自己动手清掉**确实持有本项目文件**的进程（不让用户去 kill）。
# 直接扫 /proc/*/fd：文件被删后符号链接仍保留原路径（形如
# "/root/.asnip/src/xxx (deleted)"），比 lsof 更准且不依赖外部命令。
# ⚠️ 绝不能用 `lsof | grep deleted` —— 任何做过包更新的 Linux 都有一堆无关
# 进程持有已删文件（sd-pam / agetty / networkd / unattended-upgrades 等），
# 那样报出来全是误报，还会诱导用户 kill -9 系统进程。必须按路径精确匹配。
# 排除自身与父进程（一键卸载是 `bash <(curl ...)`，父进程是用户的 shell）。
SELF_PID=$$
PARENT_PID="$PPID"
for fddir in /proc/[0-9]*/fd; do
    pid="${fddir#/proc/}"
    pid="${pid%/fd}"
    [ "$pid" = "$SELF_PID" ] && continue
    [ "$pid" = "$PARENT_PID" ] && continue
    if ls -l "$fddir" 2>/dev/null | grep -qF "$INSTALL_DIR"; then
        kill -9 "$pid" 2>/dev/null || true
    fi
done
sleep 1

# 句柄释放后再删一次，确保目录真正消失、磁盘空间真正回收
rm -rf "$INSTALL_DIR" 2>/dev/null || true

# 删“直接在仓库/当前目录运行 asnip.py”时产生的运行时产物
# （asnip.py 以脚本所在目录为 workdir，会在该目录写出下列文件）
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
CUR_DIR="$(pwd)"
for d in "$SCRIPT_DIR" "$CUR_DIR"; do
    [ -z "$d" ] && continue
    rm -f "$d/report.csv" "$d/report.json" 2>/dev/null || true
    rm -f "$d"/AS*_*_*.csv "$d"/AS*_*_*.json 2>/dev/null || true
    rm -f "$d"/output_*.csv "$d"/output_*.json 2>/dev/null || true
    rm -rf "$d/scan_data" "$d/cache" "$d/work" 2>/dev/null || true
done

# 我们装的 Python 包
# install.sh 会 `pip install maxminddb`（读 GeoLite2 mmdb 用），卸载一并移除。
# 只删这一个包 —— 不动 pip 自身、不动系统 Python 环境。
# 有些发行版是 externally-managed（PEP 668），加 --break-system-packages 兜底。
if command -v python3 >/dev/null 2>&1; then
    if python3 -c "import maxminddb" 2>/dev/null; then
        python3 -m pip uninstall -y -q maxminddb 2>/dev/null \
          || python3 -m pip uninstall -y -q --break-system-packages maxminddb 2>/dev/null \
          || true
    fi
fi

# 从 PATH 里去掉（兼容旧版可能添加的）
for f in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile"; do
    if [ -f "$f" ]; then sed -i "/\.asnip\/bin/d" "$f" 2>/dev/null || true; fi
done

# 清掉旧版可能残留的函数定义
for f in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$f" ]; then
        sed -i '/^# ASNIPtest:/,/^}/d' "$f" 2>/dev/null || true
    fi
done

# 凭据目录 ~/.config/asnip：
#   - mmdb 缓存等一切内容：**无条件删除**，不询问
#   - MaxMind Key：唯一需要征求意见的东西（重装免重输），问一句
# 用户要求："除了 key 其他我们产生的都删除"——所以先无条件清掉 Key 以外的
# 全部内容，再单独问 Key。
# 注：面板访问令牌是一次性的（attach 时生成、detach 即失效），不落盘。
ASNIP_CRED_DIR="${HOME}/.config/asnip"
MM_KEY_FILE="${ASNIP_CRED_DIR}/maxmind.key"
CRED_MSG=""
if [ -d "$ASNIP_CRED_DIR" ]; then
    # 1) Key 以外的一切（mmdb 缓存约 77MB 等）无条件删除
    find "$ASNIP_CRED_DIR" -mindepth 1 ! -path "$MM_KEY_FILE" \
         -delete 2>/dev/null || true

    # 2) 只为 Key 问一句
    if [ -s "$MM_KEY_FILE" ]; then
        DEL_KEY=""
        if exec 3<>/dev/tty 2>/dev/null; then
            printf "  删除已保存的 MaxMind License Key 吗？(y/N，保留可免重输): " >&3
            # -t 60：万一在半交互环境（有 tty 但没人应答）也不会永久卡住，
            # 超时按默认「保留」处理。
            read -t 60 -r DEL_KEY <&3 || DEL_KEY=""
            exec 3<&- 3>&- 2>/dev/null || true
            printf "\n" >&2 2>/dev/null || true
        fi
        case "$DEL_KEY" in
            y|Y|yes|YES)
                rm -rf "$ASNIP_CRED_DIR" 2>/dev/null || true
                CRED_MSG="     ${ASNIP_CRED_DIR}（含 MaxMind Key，已全部删除）"
                ;;
            *)
                CRED_MSG="     ${ASNIP_CRED_DIR} 仅保留 maxmind.key（其余已删）"
                ;;
        esac
    else
        rm -rf "$ASNIP_CRED_DIR" 2>/dev/null || true
        CRED_MSG="     ${ASNIP_CRED_DIR}（无 Key，整目录已删除）"
    fi
fi

echo ""
echo "  [OK] 卸载完成！已清理:"
echo "     ${INSTALL_DIR}（程序、扫描数据、cache、mmdb）"
echo "     /usr/local/bin/{irds,irds-result,irds-http,irds-progress,ips}"
echo "     screen/tmux asnip session"
echo "     /tmp 下的 asnip-*、GeoLite2 解压残留、get-pip.py"
echo "     pip 包 maxminddb、PATH 条目、shell 函数残留"
# 注意：这里必须用 if，不能写 `[ -n "$X" ] && echo`
# —— 那是脚本最后一条语句，$X 为空时它的退出码 1 会成为整个脚本的退出码，
# 让"什么都没装时卸载"看起来像失败。
if [ -n "$CRED_MSG" ]; then
    echo "$CRED_MSG"
fi

exit 0
