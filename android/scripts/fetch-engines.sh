#!/usr/bin/env bash
# =====================================================================
# fetch-engines.sh — ينزّل نوى الاتصال الأصلية لتطبيق bahrain-vpn مع فحص SHA-256:
#   1) sing-box (كـ libsingbox.so داخل jniLibs لتنفيذ البروتوكولات)
#   2) hev-socks5-tunnel.aar (نفق TUN ← SOCKS5 عالي الأداء مع MapDNS)
# =====================================================================
set -euo pipefail

SINGBOX_VERSION="${SINGBOX_VERSION:-1.14.4}"
HEV_TUN_VERSION="${HEV_TUN_VERSION:-2.19.3}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
JNI="$HERE/app/src/main/jniLibs"
LIBS="$HERE/app/libs"

# بصمات SHA-256 الموثّقة للإصدارات المثبّتة
SB_ARM64_SHA256="fb3a6c5197f4044f82c8fd75e01ce14c28b6abdd4c3df84bb987d41a962a320f"
SB_AMD64_SHA256="e72a8eead1ace9ce84a4ed07dfbf364e87562b736463fc00967b845cf9b3b8ac"
HEV_AAR_SHA256="ab6c581e6157680cfe5687ee7bbdcf95405c006c2db3701879ec44b9e5f83836"

verify_hash() {
  local file="$1" expected="$2"
  if [[ -n "$expected" ]]; then
    echo "${expected}  ${file}" | sha256sum -c -
  fi
}

fetch_singbox() {   # $1 = ABI في jniLibs   $2 = اسم الأصل   $3 = SHA256 المتوقّع
  local abi="$1" asset="$2" expected_sha="${3:-}"
  local url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-${asset}.tar.gz"
  local tmp; tmp="$(mktemp -d)"
  echo "→ sing-box: $abi  ←  $asset (v${SINGBOX_VERSION})"
  curl -fsSL --retry 4 --retry-delay 2 --retry-connrefused -o "$tmp/sb.tar.gz" "$url"
  if [[ "$SINGBOX_VERSION" == "1.14.4" ]]; then
    verify_hash "$tmp/sb.tar.gz" "$expected_sha"
  fi
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
  if [[ "$HEV_TUN_VERSION" == "2.19.3" ]]; then
    verify_hash "$LIBS/hev-socks5-tunnel.aar" "$HEV_AAR_SHA256"
  fi
  ls -lh "$LIBS/hev-socks5-tunnel.aar" | awk '{print "   الحجم:", $5}'
}

fetch_singbox arm64-v8a android-arm64 "$SB_ARM64_SHA256"
if [[ "${1:-}" == "--all" ]]; then
  fetch_singbox x86_64 android-amd64 "$SB_AMD64_SHA256"
fi
fetch_hev_tun

echo
echo "تم تجهيز النوى والتحقّق من بصماتها SHA-256 بنجاح:"
echo "  • $JNI"
echo "  • $LIBS/hev-socks5-tunnel.aar"
