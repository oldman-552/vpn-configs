# Bahrain Configs — تطبيق أندرويد

ينزّل القائمة الحيّة تلقائيًا من مستودع `oldman-552/vpn-configs`، **يفحصها فعليًا على شبكة هاتفك** عبر نواة `sing-box` المدمجة، وينتج ملفات جاهزة للاستيراد بضغطة زر في **v2rayNG / Hiddify / NekoBox**:

| الملف | المحتوى |
|---|---|
| `best100.txt` | أفضل 100 كانفيغ بعد الفحص الحقيقي على شبكتك مع التنويع بين الخوادم (`ping` + `KB/s`) |
| `sub.txt` | نفس أفضل النتائج بترميز Base64 كملف اشتراك محلي |
| `config.txt` | كل الكانفيغات الحيّة التي تم تنزيلها |

## المميزات الجاهزة

- **يعمل فور التثبيت بدون إعداد:** مضبوط افتراضيًا على `oldman-552/vpn-configs` ويحمّل القائمة تلقائيًا عند أول تشغيل مع حفظ الكاش والنتائج محليًا.
- **استيراد بضغطة واحدة:** فتح الاشتراك مباشرة في `Hiddify` أو `v2rayNG`، أو نسخ أفضل الكانفيغات للحافظة، أو مشاركة الملفات.
- **تصفية حسب البروتوكول:** تصفية النتائج الحية (`VLESS`, `HYSTERIA2`, `TROJAN`, `VMESS`, `SS`, `TUIC`) ونسخ أو فتح أي عقدة فرديًا.
- **مجمّع منافذ آمن ودعم الإيقاف الفوري:** تشغيل متوازٍ معزول لكل عملية `sing-box` بدون تصادم منافذ.

## البنية

```
android/
├── app/src/main/java/com/bahrain/vpnconfigs/
│   ├── MainActivity.kt            # Material 3 + RTL + 4 تبويبات + مشاركة واستيراد
│   ├── engine/
│   │   ├── Converters.kt          # URI → outbound sing-box (يدعم قفز منافذ Hysteria2 و Outline و IPv6)
│   │   ├── Socks.kt               # socks5h + TLS يدويًا مع التحقق من الهوية وإغلاق آمن للمقابس
│   │   ├── SingBox.kt             # تشغيل النواة وفحص كل عقدة
│   │   └── Tester.kt              # مجمّع منافذ متوازٍ: اتصال ← سرعة ← ترتيب
│   ├── data/{Repo,Prefs}.kt       # jsDelivr + بدائل، كاش محلي، تنويع الخوادم، إعدادات
│   ├── ui/{Theme,Screens,AppViewModel}.kt
│   └── work/RefreshWorker.kt      # تحديث القائمة دوريًا كل ساعة في الخلفية
└── scripts/fetch-engines.sh       # ينزّل sing-box ويضعه كـ libsingbox.so
```

## البناء

### عبر GitHub Actions
يُبنى التطبيق آليًا عبر `.github/workflows/apk.yml` ويرفع `app-release.apk` (موقّع وجاهز للتثبيت) إلى **Releases** و **Artifacts**.

### محليًا
```bash
cd android
bash scripts/fetch-engines.sh --all
gradle assembleDebug assembleRelease
```
المتطلبات: JDK 17 + Android SDK (platform 34) + Gradle 8.7.
