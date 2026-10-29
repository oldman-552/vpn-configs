# Bahrain Configs — مولّد كانفيغات VPN مع فحص حقيقي

منظومة من طبقتين:

```
GitHub Actions (كل 30 دقيقة)                تطبيق أندرويد
──────────────────────────────              ──────────────────────────
277 قناة تلغرام + 13 مستودع GitHub           ينزّل alive.txt (~200KB)
        ↓ 39,000 كانفيغ                      يمزج العيّنة بين البروتوكولات
تنظيف + إزالة تكرار                          يفحصها فعليًا عبر نواة sing-box
        ↓                                    على شبكة هاتفك (generate_204)
فحص اتصال حقيقي (Xray + sing-box)            يقيس سرعة أفضل N
        ↓ ~1,000 حيّة                        ↓
نشر في فرع data عبر jsDelivr                 يكتب config.txt + best100.txt
                                              ويشاركها مع v2rayNG/Hiddify
```

**الفكرة:** الخادم يقلّص العدد (رخيص وسريع)، والهاتف يقرّر الأفضل **لشبكتك أنت** —
لأن عقدة سريعة على خادم أوروبي قد تكون ميتة عندك.

---

## 1) الخادم (GitHub Actions)

### التشغيل
1. ارفع المشروع إلى مستودع **Public** (المجاني للجدولة الكثيفة).
2. `Actions → data → Run workflow` (أو انتظر 30 دقيقة).
3. سيُنشأ فرع `data` تلقائيًا:

```
https://cdn.jsdelivr.net/gh/OWNER/REPO@data/alive.txt       ← التطبيق يستخدم هذا
https://cdn.jsdelivr.net/gh/OWNER/REPO@data/best100.txt
https://cdn.jsdelivr.net/gh/OWNER/REPO@data/sub.txt         ← اشتراك base64
https://cdn.jsdelivr.net/gh/OWNER/REPO@data/alive.json
https://cdn.jsdelivr.net/gh/OWNER/REPO@data/all.txt.gz
https://cdn.jsdelivr.net/gh/OWNER/REPO@data/meta.json
```

### الملفات
| ملف | الوظيفة |
|---|---|
| `.github/workflows/data.yml` | الجدولة + الجمع + الفحص + النشر (commit واحد يُستبدل → لا انتفاخ) |
| `server/build_data.py` | منطق الدورة: جمع → تنظيف → فحص → بناء `dist/` |
| `collector.py` | جمع تلغرام + GitHub (regex، base64، retry، كتابة ذرّية) |
| `tester.py` | محرّك الفحص (Xray + sing-box) — نفس المنطق المستخدم في التطبيق |
| `github_sources.txt` / `channels.txt` | قوائم المصادر |

### متغيّرات البيئة (في `data.yml`)
`TEST_TOP=1200` • `CONCURRENCY=40` • `TEST_TIMEOUT=5` • `BEST_N=100` • `MAX_PER_HOST=3`

### نتيجة تشغيل حقيقي
```
جمع: 46,377 → نظيف: 39,602
فحص: 250 → حيّة 96   (بتوزيع متوازن: vless/ss/trojan/vmess/hysteria2/tuic)
المخرجات: alive.txt 12KB • best100.txt 14KB • all.txt.gz 2.2MB • meta.json
الزمن: 44 ثانية (بعيّنة 250؛ العيّنة الكاملة 1200 تستغرق ~3–4 دقائق)
```

---

## 2) التطبيق (أندرويد)

```bash
# بناء عبر GitHub Actions: Actions → apk → Run workflow → Artifacts
# أو محليًا:
cd android && bash scripts/fetch-engines.sh --all && gradle assembleDebug
```

بعد التثبيت: **الإعدادات ← OWNER و REPO** → «تنزيل القائمة» → «ابدأ الفحص»
→ الملفات ← شارك `best100.txt` إلى v2rayNG.

تفاصيل كاملة: [`android/README.md`](android/README.md)

---

## 3) الاستخدام اليدوي (سطر الأوامر)

```bash
pip install -r requirements.txt

python collector.py                       # جمع فقط → config.txt
python collector.py --test                # جمع + فحص + أفضل 100 → best.txt
python collector.py --test --test-top 1500 --speed-top 400 --concurrency 24
python tester.py -i config.txt --best 100  # إعادة فحص ملف جاهز
TEST_TOP=400 python server/build_data.py   # دورة الخادم محليًا → dist/
```

### نتائج الفحص (مرجعية)
| بروتوكول | النجاح عبر sing-box (مُتحقَّق) |
|---|---|
| ss | 10/10 |
| hysteria2 | 8/8 |
| hy2 | 6/6 |
| vmess | 9/10 |
| trojan | 8/10 |
| vless | 10/12 (الفشل بسبب نقل `xhttp` غير المدعوم) |

---

## 4) مرجع المصادر
- أفضل مستودعات الاشتراك المُتحقَّقة (نجوم/تحديث/حجم): [`sources.md`](sources.md)
- تقييم الكود الأصلي وأخطاؤه: [`review.md`](review.md)

---

## 5) ملاحظات مهمة
1. **المستودع Public** → ملفاتك مرئية للجميع (بديل Private يحدّ الجدولة بـ ~الساعة).
2. **cron جت‌هب غير دقيق** (تأخير 5–20 دقيقة وقت الذروة) — لذلك اخترنا 30 دقيقة لا 15.
3. **الأمان:** مشغّل أي عقدة مجانية يرى وجهاتك وSNI — لا تسجّل دخولًا لحسابات حساسة.
4. **النتائج تخصّ شبكتك:** «أفضل 100» يتغيّر بتغيّر الشبكة/المزوّد.
5. **قانونيًا:** إعادة نشر كانفيغات قنوات عامة قد يخالف شروط الخدمة في بعض البلدان.
6. **لا يتصل التطبيق بنفسه** كـ VPN (لا VpnService بعد)؛ ينتج ملفات لعميل خارجي.
