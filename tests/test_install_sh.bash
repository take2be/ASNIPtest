#!/usr/bin/env bash
# install.sh 的模拟实测：用伪造的 PATH + stub 命令，验证 6 处修复分支真的走对。
# 不真装系统依赖、不碰 /usr/local/bin、不真连网。
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# 复制到 /tmp 跑，让 install.sh 的 SCRIPT_SRC 不在仓库内 → 强制走“下载”分支
cp "$REPO_ROOT/install.sh" /tmp/install_test.sh
INSTALL_SH="/tmp/install_test.sh"
FAKE_BIN="$REPO_ROOT/tests/.fakebin"
PASS=0; FAIL=0

real_tools() {
  for c in bash grep sed curl wget tar rm cp mkdir cat chmod head tail awk readlink realpath git ln apt; do
    local p; p="$(command -v "$c" 2>/dev/null)"
    if [ -n "$p" ] && [ ! -e "$FAKE_BIN/$c" ]; then
      cp -f "$p" "$FAKE_BIN/$c" 2>/dev/null || true
    fi
  done
}

# 默认 stub：让下载步骤“成功”地写出一个非空占位 tar.gz，并让 tar 变 no-op，
# 从而脚本能继续走到步骤 3/4/完成，触发我们要测的 apt/masscan/symlink 分支。
default_stubs() {
  # python3 stub（覆盖 WindowsApps 空壳）
  cat > "$FAKE_BIN/python3" <<'EOF'
#!/usr/bin/env bash
if [ "$1" = "--version" ]; then echo "Python 3.11.15"; exit 0; fi
if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then exit 0; fi
exit 0
EOF
  chmod +x "$FAKE_BIN/python3"

  # wget/curl：把 -O 目标写成非空占位（模拟下载成功）
  cat > "$FAKE_BIN/wget" <<'EOF'
#!/usr/bin/env bash
args=("$@"); tgt=""; i=0
while [ $i -lt ${#args[@]} ]; do
  if [ "${args[$i]}" = "-O" ]; then tgt="${args[$((i+1))]}"; fi
  i=$((i+1))
done
echo "fake-tarball" > "$tgt"
exit 0
EOF
  chmod +x "$FAKE_BIN/wget"

  cat > "$FAKE_BIN/curl" <<'EOF'
#!/usr/bin/env bash
# 支持 -o <file> 写出非空占位
tgt=""; i=0; args=("$@")
while [ $i -lt ${#args[@]} ]; do
  if [ "${args[$i]}" = "-o" ]; then tgt="${args[$((i+1))]}"; fi
  i=$((i+1))
done
[ -n "$tgt" ] && echo "fake-tarball" > "$tgt"
exit 0
EOF
  chmod +x "$FAKE_BIN/curl"

  # sudo stub：默认成功 passthrough（模拟有 sudo 的 Linux）
  cat > "$FAKE_BIN/sudo" <<'EOF'
#!/usr/bin/env bash
exec "$@"
EOF
  chmod +x "$FAKE_BIN/sudo"

  # apt stub：默认成功（模拟 apt 可用；用例可覆盖为失败/删除）
  cat > "$FAKE_BIN/apt" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "$FAKE_BIN/apt"
  cat > "$FAKE_BIN/tar" <<'EOF'
#!/usr/bin/env bash
# install.sh 执行 `tar xzf master.tar.gz -C /tmp/asnip-dl/`，期望解出 ASNIPtest-master/
# 这里不真解压，仅创建该目录以模拟解压成功（避免依赖真实 tarball 结构）。
mkdir -p /tmp/asnip-dl/ASNIPtest-master
touch /tmp/asnip-dl/ASNIPtest-master/keep
exit 0
EOF
  chmod +x "$FAKE_BIN/tar"
}

build_fakebin() {
  rm -rf "$FAKE_BIN"; mkdir -p "$FAKE_BIN"
  real_tools
  default_stubs
}

run_install() {
  build_fakebin
  PATH="$FAKE_BIN:$PATH" bash "$INSTALL_SH" < /dev/null 2>&1
}

check() {
  local name="$1" expect="$2" hay="$3"
  if printf '%s' "$hay" | grep -qF -- "$expect"; then
    echo "  PASS: $name"
    PASS=$((PASS+1))
  else
    echo "  FAIL: $name  (expected: $expect)"
    FAIL=$((FAIL+1))
  fi
}

echo "== 用例1: 非 apt 系统（无 apt）应打印 apt 系警告 =="
build_fakebin
rm -f "$FAKE_BIN/apt"
OUT=$(PATH="$FAKE_BIN:$PATH" bash "$INSTALL_SH" < /dev/null 2>&1)
check "no-apt warning" "未检测到 apt" "$OUT"

echo "== 用例2: 有 apt 但 masscan 装不上（apt 对 masscan 返回非0）应提示失败而非中断 =="
build_fakebin
# apt 默认成功，但安装 masscan 时返回非0（精确模拟“masscan 装不上”）
cat > "$FAKE_BIN/apt" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do
  if [ "$a" = "masscan" ]; then exit 1; fi
done
exit 0
EOF
chmod +x "$FAKE_BIN/apt"
OUT=$(PATH="$FAKE_BIN:$PATH" bash "$INSTALL_SH" < /dev/null 2>&1)
check "masscan install fail warning" "masscan 安装失败" "$OUT"
check "script reached completion" "安装完成" "$OUT"

echo "== 用例3: symlink 无权限（ln 永远失败）应给出手动加 PATH 指引 =="
build_fakebin
cat > "$FAKE_BIN/ln" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$FAKE_BIN/ln"
OUT=$(PATH="$FAKE_BIN:$PATH" bash "$INSTALL_SH" < /dev/null 2>&1)
check "symlink fail guidance" "无权限写入 /usr/local/bin" "$OUT"
check "symlink manual path hint" "export PATH" "$OUT"

echo "== 用例4: tar.gz 下载为空应明确报错退出（wget 写成空文件） =="
build_fakebin
cat > "$FAKE_BIN/wget" <<'EOF'
#!/usr/bin/env bash
args=("$@"); tgt=""; i=0
while [ $i -lt ${#args[@]} ]; do
  if [ "${args[$i]}" = "-O" ]; then tgt="${args[$((i+1))]}"; fi
  i=$((i+1))
done
: > "$tgt"
exit 0
EOF
chmod +x "$FAKE_BIN/wget"
OUT=$(PATH="$FAKE_BIN:$PATH" bash "$INSTALL_SH" < /dev/null 2>&1)
check "empty tar.gz error" "下载失败：master.tar.gz 为空或不存在" "$OUT"

echo "== 用例5: uninstall 连项目根一起删（修复你反馈的'只删 ~/.asnip 残留项目根'）=="
# 用临时 HOME 模拟 VPS：项目装在 $HOME/ASNIPtest，含 asnip.py + pipeline/ 及运行产物
UH=$(mktemp -d)
PRJ="$UH/ASNIPtest"
mkdir -p "$PRJ/pipeline" "$UH/.asnip/bin"
touch "$PRJ/asnip.py" "$PRJ/pipeline/__init__.py" "$PRJ/cf-scanner" "$PRJ/AS36002_443_x.csv"
touch "$UH/.asnip/bin/irds"
# 标记文件指向项目根（install.sh 新版会写）
echo "$PRJ" > "$UH/.asnip/.install_root"
HOME="$UH" bash "$REPO_ROOT/uninstall.sh" >/dev/null 2>&1
if [ ! -d "$PRJ" ] && [ ! -d "$UH/.asnip" ]; then
  echo "  PASS: uninstall 删除项目根 + .asnip"
  PASS=$((PASS+1))
else
  echo "  FAIL: 卸载后残留: project_root=$([ -d "$PRJ" ] && echo yes || echo no) .asnip=$([ -d "$UH/.asnip" ] && echo yes || echo no)"
  FAIL=$((FAIL+1))
fi
rm -rf "$UH"

echo ""
echo "==== RESULT: PASS=$PASS FAIL=$FAIL ===="
rm -rf "$FAKE_BIN" /tmp/install_test.sh
[ "$FAIL" -eq 0 ]
