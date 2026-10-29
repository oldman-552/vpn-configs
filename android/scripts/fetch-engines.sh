#!/usr/bin/env bash
# =====================================================================
# fetch-engines.sh — ينزّل نواة sing-box الأندرويد ويضعها كـ libsingbox.so
# داخل jniLibs حتى تصبح قابلة للتنفيذ داخل التطبيق.
#
# الاستخدام:
#   bash scripts/fetch-engines.sh            # arm64-v8a فقط (الهواتف الحديثة)
#   bash scripts/fetch-engines.sh --all      # + x86_64 (للمحاكي)
# =====================================================================
set -euo pipefail

VERSION="${SINGBOX_VERSION:-1.14.4}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
JNI="$HERE/app/src/main/jniLibs"

fetch() {           # $1 = ABI في jniLibs   $2 = اسم الأصل في إصدار sing-box
  local abi="$1" asset="$2"
  local url="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-${asset}.tar.gz"
  local tmp; tmp="$(mktemp -d)"
  echo "→ $abi  ←  $asset (v${VERSION})"
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
  # اسم يبدأ بـ lib وينتهي بـ .so حتى يعامله أندرويد كمكتبة أصلية ويستخرجه
  cp "$bin_src" "$JNI/$abi/libsingbox.so"
  chmod +x "$JNI/$abi/libsingbox.so"
  rm -rf "$tmp"
  ls -lh "$JNI/$abi/libsingbox.so" | awk '{print "   الحجم:", $5}'
}

fetch arm64-v8a android-arm64
if [[ "${1:-}" == "--all" ]]; then
  fetch x86_64 android-amd64
fi

echo
echo "تم. الملفات في: $JNI"
