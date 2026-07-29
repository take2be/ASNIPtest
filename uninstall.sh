1|#!/usr/bin/env bash
2|# ASNIPtest 一键卸载脚本
3|35|set -euo pipefail
36|
37|INSTALL_DIR="${HOME}/.asnip"
38|
39|echo "🗑  ASNIPtest 卸载中..."
40|
41|# 删所有可能的命令入口
42|rm -f /usr/local/bin/asnip 2>/dev/null || true
43|rm -f "${HOME}/.local/bin/asnip" 2>/dev/null || true
44|rm -f "${HOME}/bin/asnip" 2>/dev/null || true
45|find /usr/local/bin -maxdepth 1 -name "asnip" \( -type l -o -type f \) -delete 2>/dev/null || true
46|
47|# 删安装目录（含 bin / src / config）
48|rm -rf "$INSTALL_DIR" 2>/dev/null || true
49|
50|# 删临时文件
51|rm -rf /tmp/asnip-dl 2>/dev/null || true
52|rm -f /tmp/asnip-install.sh 2>/dev/null || true
53|
54|# 从 PATH 里去掉
55|for f in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.bash_profile"; do
56|    if [ -f "$f" ]; then sed -i "/\.asnip\/bin/d" "$f" 2>/dev/null || true; fi
57|done
58|
59|echo "✅ 卸载完成"
60|echo "   已清理: ~/.asnip、/usr/local/bin/asnip、~/.local/bin/asnip、PATH 条目、临时缓存"
61|
62|