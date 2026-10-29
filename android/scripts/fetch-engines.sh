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
  echo "→ $abi  ←  $asset"
  curl -fsSL --retry 3 -o "$tmp/sb.tar.gz" "$url"
  tar xzf "$tmp/sb.tar.gz" -C "$tmp"
  mkdir -p "$JNI/$abi"
  # اسم يبدأ بـ lib وينتهي بـ .so حتى يعامله أندرويد كمكتبة أصلية ويستخرجه
  cp "$(find "$tmp" -type f -name sing-box | head -1)" "$JNI/$abi/libsingbox.so"
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
echo "ملاحظة: أضف jniLibs/ إلى .gitignore إن لم ترغب برفع ~80MB للمستودع."
