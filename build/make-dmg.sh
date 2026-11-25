#!/bin/bash
# 打包 macOS 安装镜像的最后一步：
#   1. 对 dist/mac-universal/Qsecret.app 做 ad-hoc 签名并校验；
#   2. 生成带「应用程序」快捷方式的 DMG（打开后把 Qsecret 拖进 Applications 即可）。
#
# 没有Apple 开发者证书时只能 ad-hoc 签名：它能保证应用包完整、在 Apple 芯片上可以运行，
# 但不能通过 Gatekeeper 的开发者认证 / 公证。首次打开需在「系统设置 → 隐私与安全性」点「仍要打开」。
#
# 用法：npm run dist:mac:dmg   （等价于 npm run dist:mac && bash build/make-dmg.sh）

set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(node -p "require('./package.json').version")"
APP="dist/mac-universal/Qsecret.app"
OUT="dist/Qsecret-${VERSION}-mac.dmg"
STAGE="dist/mac-universal"

if [ ! -d "$APP" ]; then
  echo "找不到 $APP，请先运行：npm run dist:mac（需要带 --universal）" >&2
  exit 1
fi

echo "→ 签名 $APP（ad-hoc）"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict --verbose=1 "$APP" 2>&1 | tail -2

echo "→ 生成 $OUT"
ln -sfn /Applications "$STAGE/Applications"
hdiutil create -volname "Qsecret" -srcfolder "$STAGE" -ov -format UDZO -quiet "$OUT"

echo "→ 校验"
hdiutil verify -quiet "$OUT" && echo "镜像校验通过"
hdiutil imageinfo "$OUT" | grep -E "^Format:|^Compressed Frames|bank-chunk-size" | head -3
ls -lh "$OUT" | awk '{print "大小：" $5}'
shasum -a 256 "$OUT"
