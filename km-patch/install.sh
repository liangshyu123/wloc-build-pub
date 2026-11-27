#!/usr/bin/env bash
set -e
WD=$(systemctl show -p WorkingDirectory --value km-verify 2>/dev/null || true)
DIR="$WD"
case "$WD" in */server) DIR=$(dirname "$WD") ;; esac
[ -f "$DIR/server/server.js" ] || DIR=/opt/km-verify
echo "服务目录: $DIR"
TMPD="${HOME:-/root}/kmdeploy"
mkdir -p "$TMPD"
curl -fsSL -o "$TMPD/server.js"   https://raw.githubusercontent.com/liangshyu123/wloc-build-pub/main/km-patch/server.js
curl -fsSL -o "$TMPD/plugin.html" https://raw.githubusercontent.com/liangshyu123/wloc-build-pub/main/km-patch/plugin.html
cp "$DIR/server/server.js" "$DIR/server/server.js.bak.$(date +%s)"
cp "$TMPD/server.js"   "$DIR/server/server.js"
cp "$TMPD/plugin.html" "$DIR/web/plugin.html"
systemctl restart km-verify
sleep 1
systemctl is-active km-verify
echo "完成 → 打开 https://km.47.254.47.138.nip.io/plugin.html 上传插件"
