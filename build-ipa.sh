#!/usr/bin/env bash
# wloc 加固版出包（只在 macOS + Xcode 上能跑）
#
#   bash build-ipa.sh                  # 默认：未签名 + ldid 打 entitlements，给 TrollStore 装
#   MODE=unsigned bash build-ipa.sh    # 纯未签名（Sideloadly 自签用）
#   TEAM=ABCDE12345 bash build-ipa.sh  # 用开发者证书签名导出
#
# 关键点：wloc 用 NetworkExtension + App Group，未签名的包装上去 VPN/隧道会失效，
# 所以 TrollStore 路线必须用 ldid 把 entitlements 写进主程序和 Tunnel 扩展。
set -euo pipefail
cd "$(dirname "$0")"

SCHEME="WLocApp-iOS"
OUT="${OUT:-wloc-hardened.ipa}"
TEAM="${TEAM:-}"
MODE="${MODE:-trollstore}"

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "✗ 找不到 xcodebuild：这台机器不是 macOS，或没装 Xcode。"
  echo "  Windows / Linux 请用 GitHub Actions 出包（见 HARDENING.md 第四节）。"
  exit 1
fi

if [ ! -d Pods ]; then
  command -v pod >/dev/null 2>&1 || { echo "✗ 需要 CocoaPods：brew install cocoapods"; exit 1; }
  pod install
fi

if [ -x ./generate_apple_wloc_p12.sh ] && [ ! -d app_wloc_certs ]; then
  ./generate_apple_wloc_p12.sh || echo "[warn] 证书脚本未跑通，工程已带 p12 可忽略"
fi

echo "== 编译 ($MODE) =="
rm -rf build
set -o pipefail
if [ -n "$TEAM" ]; then
  xcodebuild -workspace WLocApp.xcworkspace -scheme "$SCHEME" -configuration Release -sdk iphoneos \
    -derivedDataPath build DEVELOPMENT_TEAM="$TEAM" -allowProvisioningUpdates | tail -40
else
  xcodebuild -workspace WLocApp.xcworkspace -scheme "$SCHEME" -configuration Release -sdk iphoneos \
    -derivedDataPath build CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" | tail -40
fi

APP="$(ls -d build/Build/Products/Release-iphoneos/*.app | head -1)"
echo "== 产物 $APP =="

plist_get() { /usr/libexec/PlistBuddy -c "Print :$2" "$1/Info.plist" 2>/dev/null || true; }

sign_ldid() { # $1=可执行文件 $2=entitlements
  local bin="$1" ent="$2"
  [ -f "$bin" ] || return 0
  if [ -f "$ent" ] && command -v ldid >/dev/null 2>&1; then
    ldid -S"$ent" "$bin" && echo "  ldid ✓ $(basename "$bin") <- $(basename "$ent")"
  else
    echo "  [warn] 没装 ldid，跳过 $(basename "$bin") 的 entitlements（TrollStore 下 VPN 可能失效）"
    echo "         安装：brew install ldid"
  fi
}

if [ "$MODE" = "trollstore" ]; then
  EXEC="$(plist_get "$APP" CFBundleExecutable)"
  sign_ldid "$APP/$EXEC" "Resources/iOS/WLocApp-iOS.entitlements"
  for appex in "$APP"/PlugIns/*.appex; do
    [ -d "$appex" ] || continue
    EX="$(plist_get "$appex" CFBundleExecutable)"
    sign_ldid "$appex/$EX" "Resources/Tunnel/WLocTunnel-iOS.entitlements"
  done
fi

if [ -n "$TEAM" ]; then
  if [ -n "$(plist_get "$APP" CFBundleExecutable)" ]; then
    /usr/bin/codesign --force --deep --sign "$TEAM" "$APP" || true
  fi
fi

rm -rf Payload "$OUT"
mkdir -p Payload
cp -R "$APP" Payload/
zip -qry "$OUT" Payload
echo "OK  $(pwd)/$OUT  $(du -h "$OUT" | cut -f1)"
echo "安装：TrollStore 直接导入；或 Sideloadly / AltStore 用 Apple ID 自签。"
