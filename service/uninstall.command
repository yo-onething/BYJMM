#!/bin/bash
# Qsecret 后台服务卸载器（macOS）
# 作用：停止后台进程、移除开机自启项。不会删除应用目录，也不会删除你的数据。
# 用法：双击运行，或在终端执行  bash service/uninstall.command

set -u

LABEL="com.qsecret.vault"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
UID_NUM="$(id -u)"

say() { printf '%s\n' "$*"; }
pause() { [ -t 0 ] || return 0; read -r -p "按回车键退出…" _ ; }

say "Qsecret 后台服务卸载"
say "────────────────────────────────"

if launchctl print "gui/$UID_NUM/$LABEL" >/dev/null 2>&1; then
  launchctl bootout "gui/$UID_NUM/$LABEL" && say "已停止后台进程并移除自启项。"
else
  say "服务当前未在运行。"
fi

if [ -f "$PLIST" ]; then
  # 移到废纸篓而不是直接删除，误操作时可以找回
  if osascript -e "tell application \"Finder\" to delete POSIX file \"$PLIST\"" >/dev/null 2>&1; then
    say "配置文件已移到废纸篓：$PLIST"
  else
    say "请手动删除配置文件：$PLIST"
  fi
fi

say ""
say "应用和数据都保留在原位，没有删除任何密码数据。"
say "之后可双击 start.command 手动启动；需要时再运行 service/install.command 重新安装。"
pause
