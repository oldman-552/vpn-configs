# bahrain-vpn — تطبيق VPN متكامل للأندرويد ومنظومة فحص وتصنيف سحابية محصّنة

منظومة متكاملة من طبقتين تعمل آليًا بالكامل تحت الاسم الموحّد **`bahrain-vpn`**:

```
GitHub Actions (كل 30 دقيقة)                     تطبيق أندرويد bahrain-vpn v2.1 (متكامل)
──────────────────────────────────               ──────────────────────────────────────────
277 قناة تلغرام + 26 تغذية GitHub منتقاة          ينزّل القوائم الحيّة بكاش تدريجي (ETag / 304)
        ↓ حراسة SSRF وحدود حجم صارمة              يعرض سيرفرات bahrain-vpn مع فلتر الدول والبروتوكول
تنظيف + إزالة تكرار خماسية الطبقات (5-Layer)       يعرض مؤشرات الجودة والاستقرار وآخر وقت فحص
        ↓                                         يفحص البينغ والسرعة محليًا على شبكة هاتفك
فحص نفق متعدد الجولات L0–L6 (Xray + sing-box)     يتّصل بالـ VPN مباشرة بضغطة زر واحدة
+ كشف دولة الخروج الحقيقية + سجل استقرار طولي     (VpnService + hev-socks5-tunnel + sing-box)
        ↓                                         مع تبديل تلقائي ذكي، سجل اتصالات، واستثناء تطبيقات
نشر ذرّي محمي (Last-Known-Good) عبر jsDelivr
```

**الفلسفة المعمارية:** السحابة تُصفّي عشرات الآلاف من الكانفيغات الخام عبر 5 طبقات لإزالة التكرار و7 مراحل تحقّق (`L0–L6`) وتنشر العُقد الحيّة مصنّفةً حسب الجودة والاستقرار والسرعة والدولة؛ أمّا تطبيق الهاتف فيمنحك الاتصال الفوري والفحص المحلي على شبكتك الفعلية.

---

## 1) القوائم والاشتراكات السحابية المتخصّصة (تتحدّث آليًا كل 30 دقيقة)

جميع الروابط التالية متوافقة مع `bahrain-vpn` وكذلك `v2rayNG` و `Hiddify` و `Streisand` و `Shadowrocket` و `NekoBox`:

| الملف | الوصف | الرابط المباشر (jsDelivr CDN) |
|---|---|---|
| **`sub.txt`** | اشتراك Base64 الشامل لجميع العُقد الحيّة | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/sub.txt` |
| **`best100.txt`** | أفضل 100 عقدة مرتّبة بالدرجة المركّبة مع تنويع المضيفين والشبكات الفرعية (`/24`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/best100.txt` |
| **`reliable.txt`** / **`reliable_sub.txt`** | الأعلى استقرارًا واعتمادية عبر الجولات المتتالية (نصي + Base64) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/reliable_sub.txt` |
| **`low_latency.txt`** | الأقلّ زمن استجابة وتذبذبًا (`Median RTT + Jitter`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/low_latency.txt` |
| **`high_throughput.txt`** | الأعلى سرعة تنزيل موثّقة عبر النفق الفعلي | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/high_throughput.txt` |
| **`protocols/*.txt`** | قوائم مفصولة حسب البروتوكول (`vless`, `trojan`, `vmess`, `ss`, `hysteria2`, `tuic`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/protocols/vless.txt` |
| **`alive.json`** | البيانات الكاملة مع الدولة والدرجة والاستقرار والتذبذب لتطبيق `bahrain-vpn` | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/alive.json` |
| **`countries.json`** | توزيع العُقد الحيّة حسب دولة الخروج مع مصدر الثقة (`exit_trace` مقابل `remark_hint`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/countries.json` |
| **`source_health.json`** | تقرير صحّة المصادر، دورة حياتها، التداخل، والإضافة الحصرية (خالٍ من الأسرار) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/source_health.json` |
| **`all.txt.gz`** | المجمع البنيوي النظيف الكامل مضغوطًا قبل الفحص | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/all.txt.gz` |
| **`meta.json`** | ملخص الدورة الشامل ومؤشرات الصحّة | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/meta.json` |

---

## 2) تطبيق الأندرويد المتكامل (`bahrain-vpn` v2.1)

- **التحميل المباشر من Releases:** من صفحة [**Releases**](https://github.com/oldman-552/vpn-configs/releases):
  - **`app-arm64-v8a-release.apk`** (~47 MB): النسخة الخفيفة الموصى بها لجميع هواتف أندرويد الحديثة (`arm64`).
  - **`app-release.apk`**: النسخة الشاملة (`Universal APK`: تدعم `arm64-v8a` + `x86_64`) للتوافق التام مع الهواتف والمحاكيات.
  - **`SHA256SUMS.txt`**: بصمات التحقق الرقمي SHA-256 لجميع حزم APK المنشورة.
- **مزايا الإصدار v2.1:**
  - اتصال VPN حقيقي مدمج (`VpnService` + `hev-socks5-tunnel` + `sing-box`) مع تبديل لحظي للسيرفر دون هدم واجهة `tun0`.
  - فلترة ديناميكية حسب **دولة الخروج** أو **البروتوكول** أو **السيرفرات المستقرة** أو **المفضلة**.
  - عرض درجة الجودة المركّبة (`0–100`)، عدد جولات الاستقرار المتتالية، التذبذب (`Jitter`)، وآخر وقت فحص.
  - اختيار نمط التغذية السحابية المفضّلة (`الذكي الشامل` / `الأكثر استقرارًا` / `الأقل تأخيرًا` / `الأعلى سرعة`) مع كاش `ETag / 304` لتوفير البيانات.
  - سجل آمن لآخر الاتصالات الناجحة (دون تخزين أي معرّفات أو كلمات مرور سرية)، وحماية تلقائية من الروابط المشوّهة أو العناوين الداخلية الخطرة.
  - استثناء التطبيقات (Split Tunneling)، DNS مشفّر (DoH)، ومربّع الإعدادات السريعة (Quick Settings Tile).

---

## 3) البنية الهندسية والملفات الرئيسية

| الملف | الوظيفة الهندسية |
|---|---|
| `pipeline_security.py` | حراسة SSRF وفحص الـ Redirects، منع عناوين الشبكات الخاصة وواجهات Metadata، التحقق من بصمات SHA-256، فك الضغط الآمن ضد Zip/Tar-Slip، وحجب بيانات الاعتماد من السجلات |
| `dedupe.py` | محرّك إزالة التكرار خماسي الطبقات (المطابقة الخام ← الهوية البروتوكولية المعيارية ← تتبّع المصدر ← تجميع الشبكات الفرعية `/24` و `/48` ← تنويع المخرجات) |
| `scoring.py` | التقييم المركّب الشفاف (`L0–L6`)، سجل الاستقرار الطولي (`NodeHistoryStore` عبر EMA)، تحديد الدولة الصادق، ودورة حياة المصادر (`SourceHealthRegistry`) |
| `collector.py` | الجامع المتوازي المحصّن لـ 277 قناة تلغرام و 26 تغذية GitHub مع عزل أخطاء كل مصدر على حدة |
| `tester.py` | الفاحص الفعلي متعدّد الجولات عبر `Xray-core` و `sing-box` في بيئة معزولة مع قياس `Median RTT` و `Jitter` وكشف دولة الخروج الحقيقية عبر `/cdn-cgi/trace` |
| `server/build_data.py` | منسّق دورة الخادم وبناء القوائم المتخصّصة مع حماية آخر نسخة صالحة (`Last-Known-Good Fallback`) عند الأعطال الطارئة |
| `source_stats.py` | أداة تدقيق التفرّد والتداخل بين المصادر + الاكتشاف المحكوم للمستودعات المرشّحة عبر `--discover` |
| `.github/workflows/{ci,data,apk}.yml` | مسارات الأتمتة المثبّتة ببصمات SHA الكاملة (`40-char SHA`) وبأقل صلاحيات ممكنة (`Least Privilege`) |

---

## 4) التشغيل اليدوي وأدوات التدقيق (CLI)

```bash
pip install -r requirements.txt

python collector.py                              # جمع وتنظيف وتسمية bahrain-vpn → config.txt
python collector.py --test                       # جمع + فحص متعدد الجولات + أفضل 100 → best.txt
python tester.py -i config.txt --best 100        # فحص ملف محلي وترتيب الأفضل
python source_stats.py --no-telegram             # قياس التفرّد والتداخل والحيوية لمصادر GitHub
python source_stats.py --no-telegram --discover  # اكتشاف محكوم لمصادر مرشّحة (pending_validation)
TEST_TOP=400 python server/build_data.py         # تشغيل دورة الخادم محليًا → dist/
pytest -v                                        # تشغيل حزمة الاختبارات الأمنية والوظيفية (27 اختبارًا)
```

---

## 5) التوثيق والقيود التشغيلية الصريحة
- سجل ومنهجية اختيار المصادر ونتائج قياس التداخل: [`sources.md`](sources.md)
- المراجعة الأمنية والمعمارية الشاملة للنظام: [`review.md`](review.md)
- **تنبيه أمني صريح:** العُقد المنشورة تُجمع من مصادر عامة مفتوحة؛ مشغّل عقدة الخروج يستطيع رؤية حركة المرور غير المشفّرة ووجهات SNI. لا تستخدم عُقدًا عامة للعمليات البنكية أو الحسابات الحساسة دون تشفير طرف لطرف (HTTPS/TLS).
- **اختلاف الشبكات:** زمن الاستجابة وحجب العناوين يختلفان باختلاف مزوّد الإنترنت؛ استخدم ميزة «فحص سريع» داخل تطبيق `bahrain-vpn` لترتيب العُقد على شبكتك الفعلية.
