# bahrain-vpn — تطبيق VPN متكامل للأندرويد ومولّد سيرفرات سحابي

منظومة متكاملة من طبقتين تعمل آليًا بالكامل تحت الاسم الموحّد **`bahrain-vpn`**:

```
GitHub Actions (كل 30 دقيقة)                تطبيق أندرويد bahrain-vpn (متكامل)
──────────────────────────────              ──────────────────────────────────
277 قناة تلغرام + 13 مستودع GitHub           ينزّل سيرفرات bahrain-vpn تلقائيًا
        ↓ ~39,000 كانفيغ                     يعرض قائمة السيرفرات الموحّدة مع الفلاتر
تنظيف + إزالة تكرار + تسمية bahrain-vpn       يفحص البينغ والسرعة على شبكة هاتفك
        ↓                                    يتّصل بالـ VPN مباشرة بضغطة زر واحدة
فحص اتصال حقيقي (Xray + sing-box)            (VpnService + hev-socks5-tunnel + sing-box)
        ↓ مئات العُقد الحيّة                  مع تبديل تلقائي ذكي واستثناء للتطبيقات
نشر في فرع data عبر jsDelivr                 وعرض حيّ للسرعة والبينغ وعنوان الخروج
```

**الفكرة:** الخادم يقلّص العدد (سريع ومجاني)، والهاتف يقرّر الأفضل **لشبكتك أنت** —
لأن عقدة سريعة على خادم أوروبي قد تكون محجوبة أو بطيئة عند مزوّدك المحلي.

---

## 1) الروابط السحابية المباشرة (تتحدّث آليًا كل 30 دقيقة)

```
https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/sub.txt         ← رابط اشتراك Base64 جاهز لـ v2rayNG / Hiddify / NekoBox
https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/best100.txt     ← أفضل 100 حسب قياس الخادم
https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/alive.txt       ← كل الكانفيغات الحيّة (يستخدمها التطبيق)
https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/alive.json
https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/all.txt.gz
https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/meta.json
```

---

## 2) تطبيق الأندرويد

- **التحميل المباشر:** من صفحة [**Releases**](https://github.com/oldman-552/vpn-configs/releases) حمّل ملف `app-release.apk` وثبّته مباشرة (التطبيق مضبوط مسبقًا على `oldman-552/vpn-configs` بدون أي إعداد يدوي).
- **البناء عبر GitHub Actions:** `Actions → apk → Run workflow` (ينتج `app-release.apk` موقّع وجاهز للتثبيت + `app-debug.apk`).
- **البناء محليًا:**
  ```bash
  cd android && bash scripts/fetch-engines.sh --all && gradle assembleDebug assembleRelease
  ```

تفاصيل التطبيق الكاملة: [`android/README.md`](android/README.md)

---

## 3) الملفات وبنية المشروع

| ملف | الوظيفة |
|---|---|
| `.github/workflows/data.yml` | الجدولة كل 30 دقيقة + الجمع + الفحص + النشر إلى فرع `data` وتفريغ كاش jsDelivr |
| `.github/workflows/apk.yml` | بناء APK موقّع (`arm64-v8a` + `x86_64`) ورفعه إلى Releases و Artifacts |
| `.github/workflows/ci.yml` | اختبارات آلية شاملة لكل وحدات النظام (`pytest`) |
| `server/build_data.py` | منطق دورة الخادم: جمع ← تنظيف ← فحص ← بناء `dist/` |
| `collector.py` | جمع تلغرام + GitHub (regex، base64 قياسي و URL-safe، تنظيف HTML/ZWNJ، كتابة ذرّية) |
| `tester.py` | محرّك الفحص الحقيقي (Xray + sing-box عبر SOCKS5h و `generate_204`) |
| `channels.txt` / `github_sources.txt` | قوائم قنوات تلغرام ومصادر GitHub |

---

## 4) الاستخدام اليدوي (سطر الأوامر)

```bash
pip install -r requirements.txt

python collector.py                       # جمع فقط → config.txt
python collector.py --test                # جمع + فحص + أفضل 100 → best.txt
python collector.py --test --test-top 1500 --speed-top 400 --concurrency 24
python tester.py -i config.txt --best 100  # إعادة فحص ملف جاهز
TEST_TOP=400 python server/build_data.py   # دورة الخادم محليًا → dist/
```

---

## 5) مراجع وملاحظات مهمة
- أفضل مستودعات الاشتراك المُتحقَّقة: [`sources.md`](sources.md)
- مراجعة الأخطاء السابقة في الكود القديم: [`review.md`](review.md)
- **الأمان:** مشغّل أي عقدة مجانية يرى وجهاتك وSNI — لا تسجّل دخولًا لحسابات بنكية أو حساسة عبر عقدة عامة.
- **النتائج تخصّ شبكتك:** «أفضل 100» يتغيّر بتغيّر الشبكة/المزوّد؛ أعد الفحص من التطبيق متى تغيّرت شبكتك.
