#!/usr/bin/env bash
# ASNIPtest 一键卸载脚本
set -e

INSTALL_DIR="${HOME}/.asnip"
BIN_LINK="/usr/local/bin/asnip"

echo "🗑  ASNIPtest 卸载中..."

# 删命令软链
rm -f "$BIN_LINK" 2>/dev/null || true

# 删 bin wrapper
rm -rf "${INSTALL_DIR}/bin" 2>/dev/null || true

# 删 config
rm -rf "${INSTALL_DIR}/config" 2>/dev/null || true

# 删 scan_data 和 cache
rm -rf "${INSTALL_DIR}/src/scan_data" 2>/dev/null || true
rm -rf "${INSTALL_DIR}/src/cache" 2>/dev/null || true

# 从 PATH 里去掉
for f in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    [ -f "$f" ] && sed -i "/\.asnip\/bin/d" "$f" 2>/dev/null || true
done

# 删主目录
rm -rf "$INSTALL_DIR" 2>/dev/null || true

echo "✅ 卸载完成"
echo "   已清理: ~/.asnip、/usr/local/bin/asnip、PATH 条目、scan_data、cache"
