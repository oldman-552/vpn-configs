#!/usr/bin/env bash
# =====================================================================
# fetch-engines.sh — ينزّل نوى الاتصال الأصلية لتطبيق bahrain-vpn:
#   1) sing-box (كـ libsingbox.so داخل jniLibs لتنفيذ البروتوكولات)
#   2) hev-socks5-tunnel.aar (نفق TUN ← SOCKS5 عالي الأداء مع MapDNS)
#
# الاستخدام:
#   bash scripts/fetch-engines.sh            # arm64-v8a + AAR (الهواتف الحديثة)
#   bash scripts/fetch-engines.sh --all      # + x86_64 (للمحاكي)
# =====================================================================
set -euo pipefail

SINGBOX_VERSION="${SINGBOX_VERSION:-1.14.4}"
HEV_TUN_VERSION="${HEV_TUN_VERSION:-2.19.3}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
JNI="$HERE/app/src/main/jniLibs"
LIBS="$HERE/app/libs"

fetch_singbox() {   # $1 = ABI في jniLibs   $2 = اسم الأصل في إصدار sing-box
  local abi="$1" asset="$2"
  local url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-${asset}.tar.gz"
  local tmp; tmp="$(mktemp -d)"
  echo "→ sing-box: $abi  ←  $asset (v${SINGBOX_VERSION})"
  curl -fsSL --retry 4 --retry-delay 2 --retry-connrefused -o "$tmp/sb.tar.gz" "$url"
  tar xzf "$tmp/sb.tar.gz" -C "$tmp"
  mkdir -p "$JNI/$abi"
  local bin_src
  bin_src="$(find "$tmp" -type f -name sing-box | head -1)"
  if [[ -z "$bin_src" || ! -s "$bin_src" ]]; then
    echo "خطأ: لم يُعثر على الملف التنفيذي sing-box داخل الأرشيف!" >&2
    rm -rf "$tmp"
    exit 1
  fi
  cp "$bin_src" "$JNI/$abi/libsingbox.so"
  chmod +x "$JNI/$abi/libsingbox.so"
  rm -rf "$tmp"
  ls -lh "$JNI/$abi/libsingbox.so" | awk '{print "   الحجم:", $5}'
}

fetch_hev_tun() {
  local url="https://github.com/heiher/hev-socks5-tunnel/releases/download/${HEV_TUN_VERSION}/hev-socks5-tunnel.aar"
  mkdir -p "$LIBS"
  echo "→ hev-socks5-tunnel.aar (v${HEV_TUN_VERSION})"
  curl -fsSL --retry 4 --retry-delay 2 --retry-connrefused -o "$LIBS/hev-socks5-tunnel.aar" "$url"
  if [[ ! -s "$LIBS/hev-socks5-tunnel.aar" ]]; then
    echo "خطأ: فشل تنزيل hev-socks5-tunnel.aar!" >&2
    exit 1
  fi
  ls -lh "$LIBS/hev-socks5-tunnel.aar" | awk '{print "   الحجم:", $5}'
}

fetch_singbox arm64-v8a android-arm64
if [[ "${1:-}" == "--all" ]]; then
  fetch_singbox x86_64 android-amd64
fi
fetch_hev_tun

echo
echo "تم تجهيز النوى بنجاح:"
echo "  • $JNI"
echo "  • $LIBS/hev-socks5-tunnel.aar"
