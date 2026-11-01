# bahrain-vpn

[![CI](https://github.com/oldman-552/vpn-configs/actions/workflows/ci.yml/badge.svg)](https://github.com/oldman-552/vpn-configs/actions/workflows/ci.yml)
[![APK](https://github.com/oldman-552/vpn-configs/actions/workflows/apk.yml/badge.svg)](https://github.com/oldman-552/vpn-configs/actions/workflows/apk.yml)
[![Release](https://img.shields.io/github/v/release/oldman-552/vpn-configs)](https://github.com/oldman-552/vpn-configs/releases/latest)

تطبيق أندرويد لتجاوز الحجب، يجمع سيرفرات V2Ray/Xray العامة تلقائيًا، ويفحصها، ويختار الأسرع لشبكتك.
واجهة عربية أساسية مع دعم الإنجليزية.

> ⚠️ **اقرأ قبل الاستخدام:** السيرفرات مجمّعة من قنوات ومصادر عامة **يديرها أشخاص مجهولون**.
> صاحب السيرفر يستطيع رؤية وجهات اتصالك وأي بيانات غير مشفّرة. استخدم مواقع HTTPS فقط،
> وتجنّب الحسابات الحساسة والبنكية. التطبيق **لتجاوز الحجب، وليس لإخفاء الهوية**.

---

## التحميل

من [صفحة الإصدارات](https://github.com/oldman-552/vpn-configs/releases/latest):

| الملف | لمن |
|---|---|
| `app-arm64-v8a-release.apk` | معظم الهواتف الحديثة |
| `app-release.apk` | نسخة شاملة لكل المعالجات |
| `app-x86_64-release.apk` | المحاكيات وأجهزة x86 |
| `app-admin-release.apk` | تطبيق المشرف فقط |
| `SHA256SUMS.txt` | بصمات التحقق من الملفات |

تحقق من الملف بعد التحميل: `sha256sum -c SHA256SUMS.txt`

**طريقة الاستخدام خطوة بخطوة:** [دليل الاستخدام](docs/USER_GUIDE.md)

## المزايا

- **اختيار فائق السرعة لأفضل 100 سيرفر + قائمة «المميزة جداً» + تحديث وفحص كل ساعة:** يفحص حزمة الـ 500 بالدفعات المتوازية عبر `sing-box` ويستمر بأقصى سرعة في الخلفية حتى عند الانتقال لتطبيقات أخرى، ويقيس سرعة التنزيل الفعلية (`600 KB`) لبناء قائمة **🔥 المميزة جداً** (بمهلة احتفاظ 6 ساعات من أول انقطاع قبل الحذف) وقائمة **🏆 أفضل 100 سيرفر** لكل شبكة (`Wi-Fi` وبيانات الجوال منفصلتان تمامًا) مع **حفظ دائم للنتائج عند إغلاق التطبيق وإعادة فتحه**، **حذف فوري للسيرفرات العادية المتوقفة**، وتحديث وفحص تلقائي منتظم **كل ساعة** يُحفظ في القوائم وقابل للإيقاف من الإعدادات.
- **توحيد معادلة الترتيب (`45%` سرعة تنزيل / `30%` استقرار / `25%` بنق وتذبذب):** موحّدة بالكامل بين الخادم والتطبيق مع استبعاد صارم لأي إعداد يحتوي `allowInsecure=1`.
- **حماية الاتصال والتبديل الذكي الفوري:** Kill Switch، ومنع تسرب DNS و IPv6، وسباق اتصال ذكي متوازٍ (`Happy Eyeballs Top-4`) عند الربط، وتبديل استباقي فوري عند ضعف الاستجابة أو اختناق سرعة التنزيل الفعلية دون قطع التصفح.
- **تحميل آخر نسخة مستقرة من داخل الإعدادات:** زر مباشر في الإعدادات ينزّل النسخة المستقرة المتوافقة مع معالج جهازك داخل مجلد التنزيلات (`Downloads`) مع التحقق التلقائي من بصمة `SHA-256` دون إظهار أي روابط خارجية.
- **استثناء التطبيقات والنطاقات:** اختر تطبيقات تتجاوز الـ VPN، ونطاقات `.ir` تخرج مباشرة افتراضيًا.
- **مشاركة الـ VPN عبر الهوتسبوت** بدون روت (بروكسي HTTP/SOCKS5).
- **بيانات موقّعة:** التطبيق يرفض قوائم السيرفرات التي لا تحمل توقيعًا صحيحًا.
- **Widget للشاشة الرئيسية**، و**إحصاءات استهلاك** حسب السيرفر والشبكة، و**تقرير تشخيص** آمن للإبلاغ عن المشاكل.

### أدوات تجاوز الحجب (مجانية)
- **اكتشاف نوع الحجب:** يفحص شبكتك (DNS أو SNI أو IP أو UDP) ويعدّل اختيار السيرفر حسب النتيجة.
- **تجزئة TLS:** تخفي اسم السيرفر عن فلاتر SNI، وتعمل تلقائيًا عند الحاجة.
- **Cloudflare WARP:** احتياط مجاني عندما تفشل كل السيرفرات.
- **سيرفرات CDN:** تُميَّز بشارة وتُفضَّل عند حجب عناوين IP.

## كيف يعمل

```
قنوات تلغرام + مصادر GitHub
        │  كل 30 دقيقة (GitHub Actions)
        ▼
جمع ← تنظيف ← إزالة التكرار ← فحص أولي ← ترتيب
        │
        ▼
فرع data: top500.json + manifest موقّع (عبر jsDelivr)
        │
        ▼
التطبيق: يتحقق من التوقيع ← فحص دفعي فائق السرعة (يعمل بالخلفية) + حفظ دائم + حذف المتوقف ← المميزة جداً + Top 100 لشبكتك (كل ساعة)
```

| المكوّن | المكان | يعمل على |
|---|---|---|
| خط جمع البيانات | `server/`، `*.py` | GitHub Actions |
| تطبيق المستخدم | `android/app/` | أندرويد 10+ |
| تطبيق المشرف | `android/admin/` | أندرويد 10+ |
| لوحة الإدارة والمراقبة | `web-admin/` | GitHub Pages |
| الفحص المجتمعي (اختياري) | `community-worker/` | Cloudflare Worker + D1 |

لا توجد خوادم VPS. كل شيء على GitHub، باستثناء الفحص المجتمعي الاختياري على Cloudflare.

## روابط البيانات

القاعدة: `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/`

| الملف | المحتوى |
|---|---|
| `top500.json` / `top500.manifest.json` / `.sig` | أفضل 500 مرشح، والبيان، والتوقيع |
| `sub.txt` | اشتراك Base64 لكل السيرفرات الحيّة |
| `best100.txt` | أفضل 100 مع تنويع المضيفين |
| `iran-top500.json` | سيرفرات مُختبرة من داخل إيران مجتمعيًا |
| `api/v1/statistics.json` | إحصاءات عامة (OpenAPI 3.1) |

التفاصيل في [`docs/API.md`](docs/API.md).

## التشغيل المحلي

```bash
pip install -r requirements.txt
pytest                                   # الاختبارات
TEST_TOP=400 python server/build_data.py # بناء البيانات في dist/
```

للأندرويد: انظر [`android/README.md`](android/README.md).

## إعداد المستودع (للمالك)

أضف في **Settings ← Secrets and variables ← Actions**:

| السر | الغرض | كيف تولّده |
|---|---|---|
| `TOP500_SIGNING_KEY_B64` | توقيع بيانات Top 500 | `python scripts/gen_manifest_signing_key.py` |
| `KEYSTORE_BASE64`، `KEYSTORE_PASSWORD`، `KEY_ALIAS`، `KEY_PASSWORD` | توقيع الـ APK بشهادة ثابتة | [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) |
| `COMMUNITY_WORKER_URL`، `COMMUNITY_EXPORT_TOKEN` | الفحص المجتمعي (اختياري) | [`community-worker/README.md`](community-worker/README.md) |

والمفتاح العام للتوقيع يُوضع في `android/gradle.properties` باسم `top500PublicKeyB64`.
بدونه يقبل التطبيق البيانات غير الموقّعة (وضع انتقالي).

## التوثيق

**للمستخدمين:** [دليل الاستخدام](docs/USER_GUIDE.md) · [حل المشاكل](docs/TROUBLESHOOTING.md)

**للمطورين:**
- [المعمارية العامة](docs/ARCHITECTURE.md) · [معمارية أندرويد](docs/ANDROID_ARCHITECTURE.md) · [قواعد البيانات](docs/DATABASE_SCHEMA.md)
- [النشر والأسرار](docs/DEPLOYMENT.md) · [الاختبارات](docs/TESTING.md) · [واجهة البيانات API](docs/API.md)
- [نموذج الأمان](docs/SECURITY_MODEL.md) · [البطارية](docs/ANDROID_BATTERY_OPTIMIZATION.md) · [المنصة المؤسسية](docs/ENTERPRISE_ARCHITECTURE_AND_OPERATIONS.md)

**عام:**
- [الأمان والإبلاغ عن الثغرات](SECURITY.md) · [الخصوصية](PRIVACY.md) · [سجل التغييرات](CHANGELOG.md)
