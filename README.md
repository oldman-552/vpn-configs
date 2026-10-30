# bahrain-vpn — منصة ULTIMATE VPN ENTERPRISE v3.1 المتكاملة (100% على GitHub)

منظومة VPN مؤسسية وسحابية متكاملة تعمل آليًا بالكامل **100% داخل بيئة GitHub دون أي خوادم خارجية (Zero VPS / Zero Third-Party Cloud)** تحت الهوية الموحّدة **`bahrain-vpn`**:

```
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                         منظومة ULTIMATE VPN ENTERPRISE v3.1 (Pure-GitHub)                     │
├───────────────────────────────────────────────┬───────────────────────────────────────────────┤
│ 1) خط الجمع والفحص السحابي (كل 30 د — data)   │ 2) تطبيق المشترك للأندرويد (User APK v3.1)    │
│ • 277 قناة تلغرام + 26 تغذية GitHub منتقاة    │ • حجم رشيق عبر R8 (27.57 MB لمعالجات ARM64)   │
│ • حراسة SSRF + إزالة تكرار خماسية الطبقات     │ • فحص تلقائي فوري للسرعة وترتيب بالأسرع تنزيلاً│
│ • فحص نفق L0–L6 عبر Xray-core + sing-box      │ • سيرفرات VIP 💎 مشفّرة للمشتركين مع منع النسخ│
│ • كشف دولة الخروج الحقيقية + استقرار طولي EMA │ • تبديل تلقائي ذكي خلال ~ثانيتين عند الانقطاع │
│ • نشر ذرّي محمي (Last-Known-Good) على @data   │ • تجربة مجانية 48 ساعة + استوديو سرعة + فحص   │
│   + حزمة التراخيص الموقّعة enterprise/bundle   │   تسرب DNS/IP + محدّث تلقائي حسب المعمارية    │
├───────────────────────────────────────────────┼───────────────────────────────────────────────┤
│ 3) تطبيق المشرف المستقل (Admin APK v3.1)      │ 4) لوحة تحكم الويب المعيارية (17 صفحة AR/EN)  │
│ • حزمة مستقلة رشيقة (2.19 MB فقط عبر R8)      │ • مستضافة على GitHub Pages (فرع gh-pages)     │
│ • توثيق ثنائي TOTP 2FA + خزنة AES-256-GCM     │ • تشفير متصفح أصيل WebCrypto بدون خادم وسيط   │
│ • إدارة المشتركين والأجهزة وعقد VIP المشفّرة   │ • دعم كامل للعربية (RTL) والإنجليزية (LTR)    │
│ • توقيع ECDSA P-256 ومزامنة عبر api.github    │ • تصدير تقارير CSV/Excel وPDF والوضع الداكن   │
└───────────────────────────────────────────────┴───────────────────────────────────────────────┘
```

---

## 1) التحميل المباشر للإصدار الرسمي `v3.1` (`Latest`) وبصمات `SHA-256`

جميع الحزم مبنية وموقّعة آليًا عبر مسار `.github/workflows/apk.yml` مع تقليص الحجم عبر **`R8 + Resource Shrinking`** واجتياز التدقيق الأمني للبايت كود (`Zero Secret / Zero Source Leaks`):

- **صفحة الإصدار الرسمي:** [**GitHub Releases — `v3.1` (Latest)**](https://github.com/oldman-552/vpn-configs/releases/tag/v3.1)

| الحزمة | الاستخدام الموصى به | الحجم | بصمة التحقق `SHA-256` | رابط التحميل المباشر |
|---|---|---:|---|---|
| **`app-arm64-v8a-release.apk`** | **تطبيق المشترك** لجميع هواتف أندرويد الحديثة (`ARM64`) | **`27.57 MB`** | `945589078b0bd4b06f64e06970fac1210b27162868af508d38319c00639907cc` | [تحميل ARM64](https://github.com/oldman-552/vpn-configs/releases/download/v3.1/app-arm64-v8a-release.apk) |
| **`app-x86_64-release.apk`** | **تطبيق المشترك** لأجهزة/محاكيات `x86_64` | **`29.38 MB`** | `c0139242b49e5850db36898a2629481aa069ac8c061c8d71ae7fd93667d0e7ab` | [تحميل x86_64](https://github.com/oldman-552/vpn-configs/releases/download/v3.1/app-x86_64-release.apk) |
| **`app-release.apk`** | **تطبيق المشترك الشامل** (`Universal`: يضم كل المعماريات) | **`54.21 MB`** | `83870c4e2047070836f6d49e3044381d5e208e88cc77e77a6079b0107fdcff11` | [تحميل Universal](https://github.com/oldman-552/vpn-configs/releases/download/v3.1/app-release.apk) |
| **`app-admin-release.apk`** | **تطبيق المشرف المستقل** (`com.bahrain.vpnadmin`) | **`2.19 MB`** | `7c75b227a6ab23584804e88523759e99f44c2becb01c5c0ea334659c3c7ecb7b` | [تحميل Admin APK](https://github.com/oldman-552/vpn-configs/releases/download/v3.1/app-admin-release.apk) |
| **`SHA256SUMS.txt`** | ملف البصمات الرقمية المجمّع لجميع الحزم | `443 B` | `6f475da18f88ff7b1b37268d5bdf05c0978d5183edf76fa49a5342a29d17a716` | [تحميل SHA256SUMS](https://github.com/oldman-552/vpn-configs/releases/download/v3.1/SHA256SUMS.txt) |

---

## 2) أبرز القدرات والتطويرات الهندسية في المنصة (`v2.2` ← `v3.1`)

### أ) تطبيق المشترك للأندرويد (`User APK v3.1` — `com.bahrain.vpnconfigs`)
1. **الفحص التلقائي للاتصال والسرعة والترتيب الفوري عند كل تحديث:**
   - بمجرد تحديث قائمة السيرفرات، يبدأ التطبيق تلقائيًا بفحص عيّنة ذكية على شبكة هاتفك الفعلية ويرتّب القائمة تدريجيًا بوضع **«الأسرع في التنزيل» (`FASTEST_DOWNLOAD`)** دون قطع جلسة الـ VPN النشطة.
2. **سيرفرات `VIP 💎` الخاصة المشفّرة للمشتركين الفعّالين فقط (`Zero-Knowledge AES-256-GCM`):**
   - تُشفّر عُقد الـ VIP داخل حزمة `bundle.json` (`vip_nodes_enc_b64`) بمعيار `AES-256-GCM` (`AAD = bahrain-vpn-vip-nodes-v31`)، ولا يُكشف مفتاح فك تشفيرها إلا داخل مغلف شهادة المشترك النشط (`envelope_b64`).
   - تظهر في أعلى القائمة بوسم **`VIP 💎`** مع فحص سرعتها تلقائيًا، **وحظر نسخ روابطها الخام إلى الحافظة أو تصديرها في الملفات النصية**، ومسحها فور انتهاء الاشتراك أو تسجيل الخروج.
3. **التبديل التلقائي الذكي خلال ~ثانيتين عند الانقطاع (`SmartFailoverEngine`):**
   - فحص تأكيدي مزدوج خلال `600ms` عند أول تعثر لنبضة النفق (لتفادي التبديل الخاطئ عند رمشة الشبكة العابرة)، ثم انتقال فوري سلس دون هدم واجهة `TUN` إلى أفضل سيرفر شغّال (**بأولوية `VIP` ← أعلى سرعة تنزيل مقاسة على الهاتف ← أقل `Ping`**) مع عزل السيرفر المتذبذب لمدة دقيقتين (`Cooldown`).
4. **مؤشرات سرعة صادقة وشارات حالة خماسية الألوان:**
   - لا يعرض التطبيق إلا السرعة المقاسة فعليًا على هاتفك، مع 5 ألوان دقيقة لحالة كل سيرفر: **رمادي** (غير مفحوص محليًا)، **أخضر** (متصل وسريع)، **برتقالي** (متصل بسرعة متوسطة)، **بنفسجي** (متصل ببطء)، و**أحمر** (حصريًا للسيرفر المفصول/الفاشل).
5. **محرك التقييم المركّب `ServerRanker` و5 أوضاع ترتيب:**
   - يدعم أوضاع: **الأسرع في التنزيل** (الافتراضي)، **الأفضل شاملاً** (`50% سرعة + 20% استجابة + 20% استقرار + 10% نجاح × معامل الحداثة`)، **الأقل Ping**، **الأكثر استقرارًا**، و**أفضل دولة**، مع الحفاظ التام على السيرفر المتصل أثناء إعادة الفرز.
6. **نظام التراخيص صفري المعرفة، التجربة المجانية 48 ساعة، وأدوات الشبكة المتقدمة:**
   - تسجيل دخول المشتركين بدون أي خادم خارجي عبر مغلفات `PBKDF2-HMAC-SHA256 (120,000)` + `AES-256-GCM` الموقّعة بـ `ECDSA P-256`.
   - **تجربة مجانية 48 ساعة** محمية ضد التلاعب بساعة الهاتف عبر `EnterpriseClock` (ربط طابع وقت الشبكة الموثوق بساعة النواة الرتيبة `elapsedRealtime`) وضد إعادة التثبيت، مع فرض قاعدة **`1 حساب = 1 جهاز`** وسقوف الاستهلاك اليومي والشهري.
   - **استوديو قياس السرعة الحقيقي** عبر النفق (`Download`, `Upload`, `Ping`, `Jitter`)، **تشخيص تسرب `DNS` و`IP` وصلاحية `TLS`**، استثناء التطبيقات (`Split Tunneling`)، `DNS over HTTPS`، ومربّع الإعدادات السريعة (`Quick Settings Tile`).
   - **محدّث تلقائي ذكي حسب معمارية المعالج (`Split ABI Auto-Updater`)** يختار حزمة `arm64-v8a` الرشيقة تلقائيًا ويتحقق من بصمة `SHA-256` قبل التثبيت، إضافةً إلى نافذة إعلانات ترويجية دوّارة من 5 صور عند التشغيل (`promo/ads.json` مع عدّاد إغلاق 3 ثوانٍ) وعزل كامل لمصادر الجلب داخل `Repo.kt` فقط.

---

### ب) المنصة المؤسسية، لوحة الويب المعيارية (17 صفحة)، وتطبيق المشرف (`Enterprise v3.1`)
1. **قاعدة بيانات SQLite علائقية مطبّعة من 24 جدولًا (`enterprise/migrations/001..003`):**
   - تغطي حسابات المشتركين (`Argon2id`)، الباقات الـ 8 (`FREE_TRIAL` حتى `LIFETIME`)، سجل التجارب المجانية، حدود وسجلات الاستهلاك، الأجهزة الموثّقة وانتهاكات تعدد الأجهزة، محاولات الدخول والحماية من التخمين، الجلسات النشطة، الخوادم وفحوصاتها الصحية، اختبارات السرعة والشبكة، إصدارات التطبيقات، تقارير الانهيارات (`CRASH`/`ANR`)، التنبيهات، الإعدادات البعيدة (`Remote Config`)، عُقد ومفاتيح `VIP`، حسابات وأدوار المشرفين (`SUPER_ADMIN`, `OPERATOR`, `AUDITOR` مع `TOTP 2FA`)، وسجل التدقيق المتسلسل ببصمات `SHA-256` المقاومة للعبث (`prev_hash -> entry_hash`).
2. **لوحة تحكم الويب المعيارية (`web-admin/` + `web-admin/modules/` على `GitHub Pages`):**
   - **17 صفحة تشغيلية كاملة** ثنائية اللغة (عربي `RTL` / إنجليزي `LTR`) بالوضعين الداكن والفاتح، تعمل بتشفير المتصفح الأصيل **WebCrypto** مباشرة مع `api.github.com` دون خادم وسيط، وتدعم إدارة المشتركين والباقات والأجهزة وعقد `VIP` المشفّرة وتصدير التقارير بصيغ `CSV/Excel` و`PDF`.
3. **تطبيق المشرف المستقل للأندرويد (`Admin APK v3.1` — `2.19 MB`):**
   - تطبيق مستقل كليًا عن تطبيق المشترك، محمي برمز `TOTP 2FA` ومفتاح الخزنة المشفّرة، يتيح من الهاتف مباشرةً إنشاء وتجديد وحظر المشتركين، تصفير ربط الجهاز، إدارة وتشغيل عُقد `VIP` المشفّرة، تعديل `Remote Config`، وإعادة توقيع ونشر `enterprise/bundle.json` فورًا.
4. **محرك التحليلات الإحصائية الصادق (`enterprise/ai_intelligence.py`) والنسخ الاحتياطي المشفّر:**
   - كشف إحصائي حقيقي للشذوذ (`Z-Score`)، تقدير احتمالية سقوط العُقد، كشف الأنماط المشبوهة لتعدد الأجهزة، وتوصية أفضل سيرفر لكل دولة ومزوّد خدمة — مع التمييز الصريح عند عدم كفاية البيانات دون أي أرقام مختلقة.
   - نسخ احتياطي ذرّي مشفّر (`sqlite3.backup` + `gzip` + `SHA-256` + `AES-256-GCM`) واستعادة موثّقة بفحص `PRAGMA integrity_check;`.

---

## 3) القوائم والاشتراكات السحابية المتخصّصة (تتحدّث آليًا كل 30 دقيقة على فرع `@data`)

جميع قوائم الاشتراك متوافقة مع تطبيق `bahrain-vpn` وكذلك `v2rayNG` و`Hiddify` و`Streisand` و`Shadowrocket` و`NekoBox` (ملاحظة: عُقد `VIP` المشفّرة معزولة داخل `enterprise/bundle.json` ولا تُنشر في القوائم العامة):

| الملف | الوصف | الرابط المباشر (`jsDelivr CDN`) |
|---|---|---|
| **`sub.txt`** | اشتراك `Base64` الشامل لجميع العُقد العامة الحيّة بوسم `bahrain-vpn` | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/sub.txt` |
| **`best100.txt`** | أفضل 100 عقدة مرتّبة بالدرجة المركّبة مع تنويع المضيفين والشبكات الفرعية (`/24`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/best100.txt` |
| **`reliable.txt`** / **`reliable_sub.txt`** | الأعلى استقرارًا واعتمادية عبر الجولات المتتالية (نصي + `Base64`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/reliable_sub.txt` |
| **`low_latency.txt`** | الأقلّ زمن استجابة وتذبذبًا (`Median RTT + Jitter`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/low_latency.txt` |
| **`high_throughput.txt`** | الأعلى سرعة تنزيل موثّقة عبر النفق الفعلي | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/high_throughput.txt` |
| **`protocols/*.txt`** | قوائم مفصولة حسب البروتوكول (`vless`, `trojan`, `vmess`, `ss`, `hysteria2`, `tuic`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/protocols/vless.txt` |
| **`alive.json`** | البيانات الكاملة للعُقد الحيّة مع الدولة والدرجة والاستقرار والتذبذب لتطبيق `bahrain-vpn` | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/alive.json` |
| **`enterprise/bundle.json`** | حزمة التراخيص الموقّعة (`ECDSA P-256`)، الإعدادات البعيدة، التحديثات، وعُقد `VIP` المشفّرة | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/enterprise/bundle.json` |
| **`promo/ads.json`** | توصيف البطاقات الترويجية الخمس الدوّارة والصور المرافقة (`ad1.png..ad5.png`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/promo/ads.json` |
| **`countries.json`** | توزيع العُقد الحيّة حسب دولة الخروج مع مصدر الثقة (`exit_trace` مقابل `remark_hint`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/countries.json` |
| **`source_health.json`** | تقرير صحّة المصادر، دورة حياتها، التداخل، والإضافة الحصرية (خالٍ من الأسرار) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/source_health.json` |
| **`all.txt.gz`** | المجمّع البنيوي النظيف الكامل مضغوطًا قبل الفحص | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/all.txt.gz` |
| **`meta.json`** | ملخص الدورة الشامل ومؤشرات الصحّة | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/meta.json` |

---

## 4) الهيكل الهندسي للمستودع والملفات الرئيسية

| المسار | الوظيفة الهندسية |
|---|---|
| `pipeline_security.py` | حراسة SSRF وفحص التحويلات، منع الشبكات الخاصة وواجهات Metadata، التحقق من بصمات `SHA-256`، فك الضغط الآمن ضد `Zip/Tar-Slip`، وحجب الأسرار من السجلات |
| `dedupe.py` | إزالة التكرار خماسية الطبقات (المطابقة الخام ← الهوية البروتوكولية المعيارية ← تتبّع المصدر ← تجميع `/24` و`/48` ← تنويع المخرجات) |
| `scoring.py` | التقييم المركّب الشفاف (`L0–L6`)، سجل الاستقرار الطولي (`NodeHistoryStore` عبر `EMA`)، تحديد الدولة الصادق، ودورة حياة المصادر |
| `collector.py` / `tester.py` | الجلب المتوازي المحصّن لـ 277 قناة تلغرام و26 تغذية GitHub + الفحص الفعلي متعدّد الجولات عبر `Xray-core` و`sing-box` وكشف دولة الخروج الحقيقية |
| `server/build_data.py` | منسّق دورة البناء السحابية، نسخ أصول `promo/` و`enterprise/`، وحماية آخر نسخة صالحة (`Last-Known-Good Fallback`) |
| `enterprise/` | نواة المنصة المؤسسية (`database.py` لـ 24 جدولًا و`migrations/001..003`، `crypto_security.py`، `ai_intelligence.py`، `publisher.py`) |
| `web-admin/` | لوحة التحكم الويب المعيارية من 17 صفحة (`index.html`, `crypto_github.js`, `app.js`, ووحدات `modules/{state_and_sync,pages_subscribers,pages_infrastructure,pages_governance}.js`) |
| `android/app/` | تطبيق المشترك `v3.1` (`vpn/{BahrainVpnService,SmartFailoverEngine,VpnState}.kt`، `enterprise/{EnterpriseLicenseGuard,AppUpdateManager,ClientDiagnosticsEngine}.kt`، `data/{Repo,ServerRanker}.kt`، وواجهات `ui/` + `ui/enterprise/`) |
| `android/admin/` | تطبيق المشرف المستقل `v3.1` (`AdminMainActivity.kt`، `AdminGitHubEngine.kt`، وقواعد تقليص `R8`) |
| `promo/` | نظام البطاقات الإعلانية الدوّارة الخمس (`ads.json` + `ad1.png..ad5.png`) |
| `.github/workflows/` | مسارات الأتمتة الأربع المثبّتة ببصمات `40-char SHA` وبأقل صلاحيات (`ci.yml`, `data.yml`, `enterprise.yml`, `apk.yml`) |

---

## 5) التشغيل اليدوي، النشر المؤسسي، والاختبارات الآلية (CLI)

```bash
pip install -r requirements.txt

# 1. جمع وفحص العُقد السحابية وبناء قوائم dist/
python collector.py                              # جمع وتنظيف وتسمية bahrain-vpn ← config.txt
python collector.py --test                       # جمع + فحص متعدد الجولات + أفضل 100 ← best.txt
python tester.py -i config.txt --best 100        # فحص ملف محلي وترتيب الأفضل
python source_stats.py --no-telegram             # تدقيق التفرّد والتداخل والحيوية لمصادر GitHub
TEST_TOP=400 python server/build_data.py         # تشغيل دورة الخادم محليًا ← dist/

# 2. توليد حزمة التراخيص الموقّعة (bundle.json) والنسخ الاحتياطي المشفّر
ENTERPRISE_MASTER_KEY="your-strong-passphrase" python -m enterprise.publisher \
  --vault enterprise/vault/enterprise_vault.enc.json \
  --alive dist/alive.json \
  --bundle-out dist/enterprise/bundle.json \
  --backup-dir dist/enterprise/backups

# 3. التحقق من لوحة الويب المعيارية وتشغيل حزمة الاختبارات الشاملة (36 اختبار pytest)
for jsf in web-admin/*.js web-admin/modules/*.js; do node --check "$jsf"; done
pytest -v
```

- **تفعيل لوحة التحكم على GitHub Pages:** ينشر سير عمل `.github/workflows/enterprise.yml` ملفات `web-admin/` تلقائيًا إلى فرع `gh-pages`؛ من إعدادات المستودع (`Settings -> Pages`) اختر الفرع `gh-pages` والمجلد `/ (root)` لتعمل اللوحة مباشرة على `https://oldman-552.github.io/vpn-configs/`.
- **الاختبارات الآلية المستمرة:**
  - **`36/36` اختبار `pytest`** (`tests/test_all.py` + `tests/test_enterprise_platform.py`) تغطي أمن خط الأنابيب، التشفير صفري المعرفة، دورة حياة التجربة المجانية 48 ساعة، عزل الأجهزة، عُقد `VIP` المشفّرة، والنسخ الاحتياطي المشفّر.
  - **`15/15` اختبار `JUnit / Robolectric`** (`:app` + `:admin`) تغطي التحقق الرقمي `ECDSA P-256`، مقاومة التلاعب بالوقت، اختيار المعمارية الذكي `Split ABI`، عُقد `VIP`، ومحرك `SmartFailoverEngine`.

---

## 6) التوثيق المرجعي والقيود الأمنية الصريحة

- التوثيق الهندسي والأمني والتشغيلي للمنصة المؤسسية (`v3.1`): [`docs/ENTERPRISE_ARCHITECTURE_AND_OPERATIONS.md`](docs/ENTERPRISE_ARCHITECTURE_AND_OPERATIONS.md)
- منهجية اختيار المصادر ونتائج قياس التفرّد والتداخل: [`sources.md`](sources.md)
- المراجعة الأمنية والمعمارية لخط الأنابيب السحابي: [`review.md`](review.md)
- **التزام الخصوصية الصارم:** لا يسجّل التطبيق ولا المنصة أي سجل تصفح، عناوين مواقع يزورها المستخدم، كلمات مرور، رسائل، أو محتوى حزم الشبكة (`Zero Traffic Sniffing`).
- **تنبيه أمني حول العُقد العامة:** العُقد العامة المنشورة في القوائم المفتوحة تُجمع من مصادر عامة؛ مشغّل عقدة الخروج يستطيع رؤية حركة المرور غير المشفّرة ووجهات `SNI`. للعمليات الحساسة استخدم دائمًا تشفير طرف لطرف (`HTTPS/TLS`) أو اعتمد على **سيرفرات `VIP 💎` الخاصة المملوكة لك** داخل حساب المشترك.
