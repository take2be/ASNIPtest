#!/usr/bin/env bash
# ASNIPtest 一键卸载脚本
set -euo pipefail

INSTALL_DIR="${HOME}/.asnip"

echo "🗑  ASNIPtest 卸载中..."
echo ""

# 删系统 PATH 下的命令入口
rm -f /usr/local/bin/irds 2>/dev/null || true
rm -f /usr/local/bin/irds-result 2>/dev/null || true
rm -f /usr/local/bin/ips 2>/dev/null || true
rm -f /usr/local/bin/asnip 2>/dev/null || true
rm -f "${HOME}/.local/bin/irds" "${HOME}/.local/bin/irds-result" 2>/dev/null || true
rm -f "${HOME}/bin/asnip" 2>/dev/null || true

# 删安装目录全部内容
rm -rf "$INSTALL_DIR" 2>/dev/null || true

# 删安装时产生的临时文件
rm -rf /tmp/asnip-dl 2>/dev/null || true
rm -f /tmp/asnip-install.sh 2>/dev/null || true

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

# 清理残留的 screen/tmux session
if command -v screen >/dev/null 2>&1; then
    if screen -ls 2>/dev/null | grep -qE '[0-9]+\.asnip'; then
        screen -ls 2>/dev/null | grep -oE '[0-9]+\.asnip' | while read -r s; do
            screen -X -S "$s" quit 2>/dev/null || true
        done
    fi
fi
if command -v tmux >/dev/null 2>&1; then
    tmux has-session -t asnip 2>/dev/null && tmux kill-session -t asnip 2>/dev/null || true
fi

echo ""
echo "  ✅ 卸载完成！已清理:"
echo "     ${INSTALL_DIR}"
echo "     /usr/local/bin/{irds,irds-result,ips}"
echo "     screen/tmux asnip session"
echo "     PATH 条目、临时缓存"
