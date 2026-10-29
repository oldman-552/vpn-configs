# Bahrain Configs — تطبيق أندرويد

يأخذ القائمة الحيّة من GitHub، **يفحصها على شبكة هاتفك**، ويكتب ملفين:

| الملف | المحتوى |
|---|---|
| `config.txt` | كل الكانفيغات التي نزّلتها (بلا تعديل) |
| `best100.txt` | أفضل 100 كانفيغ بعد الفحص الحقيقي على شبكتك، مع `ping` و`KB/s` في الـ remark |

ثم تشاركها بزر إلى **v2rayNG / Hiddify / NekoBox**.

## البنية

```
android/
├── app/src/main/java/com/bahrain/vpnconfigs/
│   ├── MainActivity.kt            # Material 3 + RTL + 4 تبويبات
│   ├── engine/
│   │   ├── Converters.kt          # URI → outbound sing-box (مُتحقَّق منه عمليًا)
│   │   ├── Socks.kt               # socks5h + TLS يدويًا (بلا مكتبات)
│   │   ├── SingBox.kt             # تشغيل النواة وفحص عقدة واحدة
│   │   └── Tester.kt              # فحص متوازٍ: اتصال ← أول N ← سرعة
│   ├── data/{Repo,Prefs}.kt       # jsDelivr + بدائل، كاش، إعدادات
│   ├── ui/{Theme,Screens,AppViewModel}.kt
│   └── work/RefreshWorker.kt      # تحديث القائمة كل ساعة (بلا فحص)
└── scripts/fetch-engines.sh       # ينزّل sing-box ويضعه libsingbox.so
```

## لماذا `libsingbox.so`؟

أندرويد منذ الإصدار 10 يمنع تنفيذ ملفات من مجلد بيانات التطبيق. الحيلة المعروفة:
تسمية الملف التنفيذي `libxxxxxxxx.so` ووضعه في `jniLibs`، فيستخرجه النظام إلى
`nativeLibraryDir` ويصبح قابلًا للتنفيذ. لذلك في `build.gradle.kts`:

```kotlin
packaging { jniLibs { useLegacyPackaging = true } }   // استخراج المكتبات
```
وفي `AndroidManifest.xml`: `android:extractNativeLibs="true"`.

## البناء

### عبر GitHub Actions (الأسهل)
ارفع المشروع، ثم شغّل `Actions → apk → Run workflow`. ستحصل على
`app-debug.apk` في **Artifacts**. الـ workflow ينزّل النواة تلقائيًا.

### محليًا
```bash
cd android
bash scripts/fetch-engines.sh --all     # arm64 + x86_64 (المحاكي)
gradle assembleDebug                    # أو ./gradlew إذا أضفت wrapper
# الناتج: app/build/outputs/apk/debug/app-debug.apk
```
المتطلبات: JDK 17 + Android SDK (platform 34) + Gradle 8.7.

## أول تشغيل
1. الإعدادات ← اكتب **OWNER** و**REPO** (اسم مستخدمك واسم المستودع).
2. الرئيسية ← «تنزيل القائمة» (تنزيل ~200KB فقط).
3. «ابدأ الفحص» ← يفحص أول 600 (متوازنة بين البروتوكولات) ثم يقيس سرعة أفضل 120.
4. الملفات ← شارك `best100.txt` إلى v2rayNG.

## الأرقام الافتراضية (قابلة للتغيير)
| الإعداد | القيمة | المعنى |
|---|---|---|
| عدد المفحوص | 600 | عيّنة متوازنة بين البروتوكولات |
| قياس السرعة | 120 | لتفادي استهلاك بيانات كبير |
| التوازي | 6 | عمليات sing-box متزامنة (1–12) |
| المهلة | 6 ثوانٍ | لكل عقدة |

## ما يعمل وما لا يعمل
- ✅ vless / vmess / trojan / ss / hysteria2 / hy2 / tuic
- ⚠️ نقل `xhttp` غير مدعوم في sing-box → يُستثنى من الفحص (يبقى في `config.txt`)
- ❌ `ssr` غير مدعوم
- ⚠️ التطبيق **لا يتصل بنفسه** كـ VPN؛ ينتج ملفات لعميل خارجي (VpnService خطوة لاحقة)
