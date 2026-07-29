#!/usr/bin/env bash
# ASNIPtest 一键卸载脚本
set -euo pipefail

INSTALL_DIR="${HOME}/.asnip"

echo "🗑  ASNIPtest 卸载中..."

# 删所有可能的命令入口
rm -f /usr/local/bin/asnip 2>/dev/null || true
rm -f "${HOME}/.local/bin/asnip" 2>/dev/null || true
rm -f "${HOME}/bin/asnip" 2>/dev/null || true
find /usr/local/bin -maxdepth 1 -name "asnip" \( -type l -o -type f \) -delete 2>/dev/null || true

# 删二进制/缓存/data/config
rm -rf "${INSTALL_DIR}/bin" 2>/dev/null || true
rm -rf "${INSTALL_DIR}/config" 2>/dev/null || true
rm -rf "${INSTALL_DIR}/src/scan_data" 2>/dev/null || true
rm -rf "${INSTALL_DIR}/src/cache" 2>/dev/null || true

# 删主目录（含 src/asnip.py、src/cf-scanner 等）
rm -rf "$INSTALL_DIR" 2>/dev/null || true

# 删安装时产生的临时文件
rm -rf /tmp/asnip-dl 2>/dev/null || true
rm -f /tmp/asnip-install.sh 2>/dev/null || true

# 从 PATH 里去掉
for f in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile"; do
    if [ -f "$f" ]; then sed -i "/\.asnip\/bin/d" "$f" 2>/dev/null || true; fi
done

echo "✅ 卸载完成"
echo "   已清理: ~/.asnip、/usr/local/bin/asnip、~/.local/bin/asnip、PATH 条目、临时缓存"
