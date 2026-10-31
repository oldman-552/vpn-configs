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

## المزايا

- **اختيار تلقائي للأسرع:** يفحص السيرفرات عبر نفق حقيقي ويرتّب أفضل 50 لكل شبكة (WiFi وبيانات الجوال منفصلة).
- **حماية الاتصال:** Kill Switch، ومنع تسرب DNS و IPv6، وإعادة اتصال تلقائية.
- **استثناء التطبيقات والنطاقات:** اختر تطبيقات تتجاوز الـ VPN، ونطاقات `.ir` تخرج مباشرة افتراضيًا.
- **مشاركة الـ VPN عبر الهوتسبوت** بدون روت (بروكسي HTTP/SOCKS5).
- **بيانات موقّعة:** التطبيق يرفض قوائم السيرفرات التي لا تحمل توقيعًا صحيحًا.

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
التطبيق: يتحقق من التوقيع ← يفحص محليًا ← Top 50 لشبكتك
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

القائمة الكاملة في [`docs/OVERVIEW.md`](docs/OVERVIEW.md) و [`API.md`](API.md).

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
| `KEYSTORE_BASE64`، `KEYSTORE_PASSWORD`، `KEY_ALIAS`، `KEY_PASSWORD` | توقيع الـ APK بشهادة ثابتة | انظر [`docs/OVERVIEW.md`](docs/OVERVIEW.md) |
| `COMMUNITY_WORKER_URL`، `COMMUNITY_EXPORT_TOKEN` | الفحص المجتمعي (اختياري) | [`community-worker/README.md`](community-worker/README.md) |

والمفتاح العام للتوقيع يُوضع في `android/gradle.properties` باسم `top500PublicKeyB64`.
بدونه يقبل التطبيق البيانات غير الموقّعة (وضع انتقالي).

## التوثيق

- [نظرة تفصيلية على المشروع](docs/OVERVIEW.md)
- [معمارية أندرويد](docs/ANDROID_ARCHITECTURE.md) · [نموذج الأمان](docs/SECURITY_MODEL.md) · [قواعد البيانات](docs/DATABASE_SCHEMA.md)
- [النشر](DEPLOYMENT.md) · [الاختبارات](TESTING.md) · [حل المشاكل](TROUBLESHOOTING.md)
- [الأمان والإبلاغ عن الثغرات](SECURITY.md) · [الخصوصية](PRIVACY.md) · [سجل التغييرات](CHANGELOG.md)
