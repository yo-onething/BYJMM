#!/bin/bash
# Qsecret 后台服务安装器（macOS）
# 作用：把应用复制到固定目录，并注册为用户级 LaunchAgent：
#       登录后自动启动、意外退出自动拉起、日志写入 ~/Library/Logs。
# 用法：双击运行，或在终端执行  bash service/install.command
# 可选环境变量：QSECRET_HOME（安装目录，默认 ~/Applications/Qsecret）
#               QSECRET_PORT（端口，默认 7878）  QSECRET_NO_OPEN=1（不自动打开浏览器）

set -u

LABEL="com.qsecret.vault"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs"
PORT="${QSECRET_PORT:-7878}"
URL="http://127.0.0.1:${PORT}"
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${QSECRET_HOME:-$HOME/Applications/Qsecret}"

say() { printf '%s\n' "$*"; }
pause() { [ -t 0 ] || return 0; read -r -p "按回车键退出…" _ ; }
die() { say ""; say "安装失败：$*"; pause; exit 1; }

xml_escape() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

# 在候选路径里挑版本最高的 Node.js（要求 18+），返回绝对路径
find_node() {
  local best="" best_major=0 c major
  for c in /opt/homebrew/bin/node /usr/local/bin/node "$HOME/.nvm/versions/node"/*/bin/node \
           "$HOME/.volta/bin/node" "$HOME/.local/bin/node" "$(command -v node 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    major="$("$c" -v 2>/dev/null | sed 's/^v\([0-9]*\).*/\1/')"
    [ -n "$major" ] || continue
    if [ "$major" -ge 18 ] 2>/dev/null && [ "$major" -gt "$best_major" ]; then
      best="$c"; best_major="$major"
    fi
  done
  [ -n "$best" ] || return 1
  # 解析符号链接，nvm 的 node 可能是链接
  best="$(cd "$(dirname "$best")" && pwd)/$(basename "$best")"
  printf '%s' "$best"
}

say "Qsecret 后台服务安装"
say "────────────────────────────────"

NODE_BIN="$(find_node)" || die "未找到 Node.js 18 或更高版本。请先安装：https://nodejs.org 或 brew install node"
say "Node.js：$NODE_BIN ($("$NODE_BIN" -v))"
say "安装到：$DEST"

# ---- 1. 复制应用（不覆盖已有数据目录）
mkdir -p "$DEST" || die "无法创建目录 $DEST"
if ! rsync -a --exclude 'data/' --exclude '.git/' --exclude 'node_modules/' --exclude '*.log' \
      --exclude '.DS_Store' "$SRC/" "$DEST/"; then
  die "复制文件失败"
fi
[ -f "$DEST/server.js" ] || die "$DEST 里没有 server.js，源目录不完整"

# ---- 2. 写入 LaunchAgent 配置
mkdir -p "$HOME/Library/LaunchAgents" "$LOG_DIR" || die "无法创建 launchd / 日志目录"

NODE_XML="$(xml_escape "$NODE_BIN")"
DEST_XML="$(xml_escape "$DEST")"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$NODE_XML</string>
    <string>$DEST_XML/server.js</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$DEST_XML</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>QSECRET_SERVICE</key>
    <string>1</string>
    <key>QSECRET_PORT</key>
    <string>$PORT</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>$LOG_DIR/qsecret.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/qsecret.error.log</string>
</dict>
</plist>
EOF
chmod 600 "$PLIST"

plutil -lint "$PLIST" >/dev/null 2>&1 || die "生成的配置文件无效：$PLIST"

# ---- 3. 注册并启动
UID_NUM="$(id -u)"
launchctl bootout "gui/$UID_NUM/$LABEL" >/dev/null 2>&1 || true
if ! launchctl bootstrap "gui/$UID_NUM" "$PLIST" 2>/tmp/qsecret-bootstrap.err; then
  die "launchd 注册失败：$(cat /tmp/qsecret-bootstrap.err)"
fi

# ---- 4. 等待服务就绪
READY=""
for _ in $(seq 1 80); do
  if curl -sf "$URL/api/state" 2>/dev/null | grep -q '"service":true'; then
    READY=1
    break
  fi
  sleep 0.25
done
[ -n "$READY" ] || die "服务已注册但没有在 $URL 响应，请查看 $LOG_DIR/qsecret.error.log"

say ""
say "已安装并启动。"
say "  地址：$URL"
say "  数据：$DEST/data/vault.qvault"
say "  日志：$LOG_DIR/qsecret.log"
say "  卸载：service/uninstall.command"
say ""
say "服务在后台运行不等于已解锁——每次打开仍需输入主密码。"

if [ "${QSECRET_NO_OPEN:-0}" != "1" ]; then
  open "$URL" 2>/dev/null || true
fi
pause
