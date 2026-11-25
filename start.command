#!/bin/bash
# Qsecret 启动器：双击运行。自动挑选 Node.js 18+，启动后打开浏览器。

cd "$(dirname "$0")" || exit 1

find_node() {
  local candidates=(
    "$HOME/.nvm/versions/node"/*/bin/node
    /opt/homebrew/bin/node
    /usr/local/bin/node
    "$(command -v node 2>/dev/null)"
  )
  for c in "${candidates[@]}"; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    local major
    major="$("$c" -v 2>/dev/null | sed 's/^v\([0-9]*\).*/\1/')"
    if [ -n "$major" ] && [ "$major" -ge 18 ] 2>/dev/null; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

NODE_BIN="$(find_node)"
if [ -z "$NODE_BIN" ]; then
  echo "未找到 Node.js 18 或更高版本。"
  echo "请安装：https://nodejs.org  或  brew install node"
  read -r -p "按回车键退出…" _
  exit 1
fi

PORT="${QSECRET_PORT:-7878}"
URL="http://127.0.0.1:${PORT}"

# 已有实例在运行（通常是为开机自启安装的后台服务）：不再重复启动，直接打开浏览器
if curl -sf "${URL}/api/state" >/dev/null 2>&1; then
  echo "Qsecret 已经在运行：${URL}"
  open "$URL"
  exit 0
fi

"$NODE_BIN" server.js &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null' EXIT INT TERM

for _ in $(seq 1 60); do
  if curl -sf "${URL}/api/state" >/dev/null 2>&1; then
    open "$URL"
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "服务启动失败，请查看上方错误信息。"
    read -r -p "按回车键退出…" _
    exit 1
  fi
  sleep 0.25
done

echo "Qsecret 正在运行：${URL}"
echo "关闭此窗口或按 Ctrl+C 即停止服务（停止后内存密钥会被抹除）。"
wait "$SERVER_PID"