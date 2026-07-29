#!/usr/bin/env bash
# ASNIPtest — 一键清理老旧/损坏安装
set -euo pipefail

INSTALL_DIR="${HOME}/.asnip"
echo "🧹 清理 ASNIPtest 临时/损坏文件..."

rm -f /usr/local/bin/asnip 2>/dev/null || true
rm -f "${HOME}/.local/bin/asnip" 2>/dev/null || true
rm -f "${HOME}/bin/asnip" 2>/dev/null || true
rm -rf "$INSTALL_DIR" 2>/dev/null || true
rm -rf /tmp/asnip-dl 2>/dev/null || true
rm -f /tmp/asnip-install.sh 2>/dev/null || true

for f in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile"; do
    if [ -f "$f" ]; then sed -i "/\.asnip\/bin/d" "$f" 2>/dev/null || true; fi
done

echo "✅ 清理完成：$INSTALL_DIR、/usr/local/bin/asnip、~/.local/bin/asnip、shell PATH、临时缓存"
