# bahrain-vpn — منصة ULTIMATE VPN ENTERPRISE v3.2 المتكاملة (الأمان الذكي، منع التسرب، مفتاح الإيقاف، وواجهة API v1 — 100% على GitHub)

منظومة VPN مؤسسية وسحابية متكاملة تعمل آليًا بالكامل **100% داخل بيئة GitHub دون أي خوادم خارجية (Zero VPS / Zero Third-Party Cloud)** تحت الهوية الموحّدة **`bahrain-vpn`**:

```
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                         منظومة ULTIMATE VPN ENTERPRISE v3.2 (Pure-GitHub)                     │
├───────────────────────────────────────────────┬───────────────────────────────────────────────┤
│ 1) الذكاء الأمني والفحص السحابي (كل 30 د)      │ 2) تطبيق المشترك للأندرويد (User APK v3.2)    │
│ • 277 قناة تلغرام + 26 تغذية GitHub منتقاة    │ • حجم رشيق عبر R8 (27.63 MB لمعالجات ARM64)   │
│ • فصل الأمان والخصوصية عن السرعة + حجر صحي    │ • منع تسرب DNS داخل النفق + حجب تسرب IPv6 ::/0│
│ • 5 ملفات ترتيب ذكية + قوائم privacy_aware    │ • مفتاح إيقاف صارم (Fail-Closed Kill Switch)  │
│ • عزل تلقائي للمصادر التالفة أو المشبوهة       │ • تبديل استباقي (OFF / SMART / AGGRESSIVE)    │
│ • واجهة إحصاءات عامة معماة (/api/v1/* + OAS3) │ • 8 حالات نفق موثّقة + فحص تلقائي وترتيب سرعة │
│   + نشر ذرّي محمي (LKG) وحزمة bundle موقّعة    │   + عقد VIP 💎 مشفّرة + تجربة 48 ساعة محمية   │
├───────────────────────────────────────────────┼───────────────────────────────────────────────┤
│ 3) تطبيق المشرف المستقل (Admin APK v3.2)      │ 4) لوحة الإدارة + شاشة المراقبة الحيّة (Web)  │
│ • حزمة مستقلة رشيقة (2.19 MB فقط عبر R8)      │ • 17 صفحة إدارة مشفّرة (index.html على Pages) │
│ • توثيق ثنائي TOTP 2FA + خزنة AES-256-GCM     │ • لوحة مراقبة عامة حيّة (monitor.html AR/EN)  │
│ • إدارة المشتركين والأجهزة وعقد VIP المشفّرة   │ • تشفير متصفح أصيل WebCrypto بدون خادم وسيط   │
│ • توقيع ECDSA P-256 ومزامنة عبر api.github    │ • مخططات تاريخية وتقارير CSV/Excel وPDF       │
└───────────────────────────────────────────────┴───────────────────────────────────────────────┘
```

---

## 1) التحميل المباشر للإصدار الرسمي `v3.2` (`Latest`) وبصمات `SHA-256`

جميع الحزم مبنية وموقّعة آليًا عبر مسار `.github/workflows/apk.yml` مع تقليص الحجم عبر **`R8 + Resource Shrinking`** واجتياز اختبارات `Robolectric` والتدقيق الأمني للبايت كود (`Zero Secret / Zero Source Leaks`):

- **صفحة الإصدار الرسمي:** [**GitHub Releases — `v3.2` (Latest)**](https://github.com/oldman-552/vpn-configs/releases/tag/v3.2)

| الحزمة | الاستخدام الموصى به | الحجم | بصمة التحقق `SHA-256` | رابط التحميل المباشر |
|---|---|---:|---|---|
| **`app-arm64-v8a-release.apk`** | **تطبيق المشترك** لجميع هواتف أندرويد الحديثة (`ARM64` — `versionCode = 10`) | **`27.63 MB`** | `13dd72d0182de10f5a5b9d75174d3626aae10759f00e79ae89efa8b0da9dfdee` | [تحميل ARM64 v3.2](https://github.com/oldman-552/vpn-configs/releases/download/v3.2/app-arm64-v8a-release.apk) |
| **`app-x86_64-release.apk`** | **تطبيق المشترك** لأجهزة/محاكيات `x86_64` (`versionCode = 10`) | **`29.44 MB`** | `11b8f1828883b1206253ddc619f4c2baa9f85a857591f767e0516a58c7353e5c` | [تحميل x86_64 v3.2](https://github.com/oldman-552/vpn-configs/releases/download/v3.2/app-x86_64-release.apk) |
| **`app-release.apk`** | **تطبيق المشترك الشامل** (`Universal`: يضم كل المعماريات) | **`54.27 MB`** | `ca21059896f59136334e47c42fec34dc1b5105d5db63c03b56062fd57aff9da9` | [تحميل Universal v3.2](https://github.com/oldman-552/vpn-configs/releases/download/v3.2/app-release.apk) |
| **`app-admin-release.apk`** | **تطبيق المشرف المستقل** (`com.bahrain.vpnadmin` — `versionCode = 3`) | **`2.19 MB`** | `f275b145cd1e82626407fe895d68a8cada44cdaea43ec857759a6d6cb8f10a29` | [تحميل Admin v3.2](https://github.com/oldman-552/vpn-configs/releases/download/v3.2/app-admin-release.apk) |
| **`SHA256SUMS.txt`** | ملف البصمات الرقمية المجمّع لجميع الحزم الموقّعة | `443 B` | `f17b9fdc7e8a0a7d23ebb763ac22ba96bfef9ecd08b81847b7ada893803df2c3` | [تحميل SHA256SUMS](https://github.com/oldman-552/vpn-configs/releases/download/v3.2/SHA256SUMS.txt) |

---

## 2) أبرز القدرات والتطويرات الهندسية في المنصة (`v2.2` ← `v3.2`)

### أ) تطبيق المشترك للأندرويد (`User APK v3.2` — `com.bahrain.vpnconfigs`)
1. **منع تسرب `DNS` و`IPv6` وشفافية `WebRTC` (`LeakProtectionEngine` + `SingBox`):**
   - فصل كامل داخل نواة `sing-box` بين محلّل التمهيد (`bootstrap` لحل اسم نطاق سيرفر البروكسي فقط) ومحلّل النفق المشفّر (`tunnel-dns` مع `"detour": "proxy"`) بحيث تمر 100% من استعلامات DNS الخاصة بالتطبيقات داخل النفق مع تطهير عناوين DNS المحلية/الخاصة (`192.168/10/127`).
   - التقاط المسار `::/0` (`fc00::1/128`) دائمًا داخل واجهة `tun0` حتى عند إيقاف توجيه IPv6 (مع فرض استراتيجية `ipv4_only`) لمنع أي تسرب لحزم IPv6 عبر شبكات الجيل الخامس والـ Wi-Fi المزدوجة (`Dual-Stack`).
   - تشخيص صادق لمخاطر `WebRTC` يرصُد استثناء المتصفحات في `Split Tunneling` ويقدّم إرشادات حماية المتصفح دون ادعاءات مضللة.
2. **مفتاح الإيقاف الصارم (`Fail-Closed Kill Switch` + `BootRestoreReceiver`):**
   - قفل واجهة `tun0` **قبل** بدء فحص السيرفر لمنع أي نافذة تسرب أثناء الربط، والاحتفاظ بالحجب الفعّال (`PROTECTION_ACTIVE`) عند سقوط جميع السيرفرات مع محاولة استعادة هادئة كل `15s`، واستعادة الحماية بعد إعادة التشغيل (`BOOT_COMPLETED`)، والتنقل السلس بين `Wi-Fi` والجيل الخامس عبر `NetworkCallback` (`RECONNECTING`)، ورصد تفعيل `OS Lockdown` في نظام أندرويد.
3. **التبديل الاستباقي الذكي ومراقبة التدهور (`SmartFailoverEngine v3.2`):**
   - ثلاث سياسات قابلة للاختيار: **`OFF`** (يدوي)، **`SMART`** (تبديل عند الانقطاع أو التدهور الشديد)، و**`AGGRESSIVE`** (انتقال استباقي لسيرفر أسرع بفارق جوهري).
   - رصد التدهور قبل الانقطاع الكامل (`CONNECTION_DEGRADED` من زمن الاستجابة، التذبذب `Jitter`، وفقدان الحزم)، منع التذبذب والحلقات (`Hysteresis 25s` + `Cooldown 120s`)، فحص مسبق للبدائل على المنافذ `20901..20904` دون قطع النفق النشط، وجدولة مراقبة تكيّفية موفّرة للبطارية (`3.5s .. 24s`).
4. **فصل الأمان والخصوصية عن السرعة (`SecurityEvaluator`) و6 أوضاع ترتيب ذكية (`ServerRanker`):**
   - تقييم مستقل لأمان النقل (`Verified / Partial / Unknown / Failed`) وخصوصية المشغّل (`Verified` حصريًا لعُقد `VIP 💎` الموثّقة، و`Unverified` للعُقد العامة النظيفة، و`High Risk` لـ `allowInsecure=1`).
   - فحص تلقائي فوري للسرعة عند كل تحديث وترتيب افتراضي بوضع **«الأسرع في التنزيل» (`FASTEST_DOWNLOAD`)** إلى جانب **الأقل تأخيرًا**، **الأكثر استقرارًا**، **الأفضل إجمالًا**، **الأعلى أمانًا وخصوصية (`PRIVACY_AWARE`)**، و**الأحدث اختبارًا** دون قطع جلسة الـ VPN النشطة.
   - عرض السرعة الحقيقية المقاسة على الهاتف فقط بـ 5 ألوان دقيقة (**رمادي** غير مفحوص، **أخضر** سريع، **برتقالي** متوسط، **بنفسجي** بطيء، **أحمر** للمنقطع فقط)، وحالات اتصال ثمان موثّقة لا تعلن `CONNECTED` إلا بعد نجاح مرور البيانات فعليًا عبر النفق.
5. **سيرفرات `VIP 💎` المشفّرة، التراخيص صفرية المعرفة، والتحديث الذكي (`Split ABI`):**
   - تشفير عُقد `VIP 💎` بمعيار `AES-256-GCM` (`AAD = bahrain-vpn-vip-nodes-v31`) للمشتركين الفعّالين فقط مع منع نسخ روابطها أو تصديرها، وتجربة مجانية `48 ساعة` محمية ضد التلاعب بساعة الجهاز (`EnterpriseClock`)، ومحدّث تلقائي يختار حزمة `arm64-v8a` الرشيقة ويتحقق من بصمة `SHA-256`، ونافذة إعلانات دوّارة من 5 صور (`promo/ads.json`).

---

### ب) المنصة المؤسسية، لوحة الإدارة (17 صفحة)، شاشة المراقبة الحيّة، وواجهة `API v1` (`Enterprise v3.2`)
1. **محرك الذكاء الأمني والحجر الصحي السحابي (`security_intelligence.py` + `collector.py`):**
   - حجر صحي مزدوج (قبل الفحص وبعد الفحص `quarantined.json`) يعزل التشفير المكسور، المنافذ المشبوهة (`22`, `445`, `3389`...)، والتحويلات المشبوهة، مع عزل تلقائي للمصادر التالفة (`source_health.json`) وتتبع تغيّرات المحتوى ببصمة `SHA-256` و`ETag/304`.
2. **واجهة الإحصاءات العامة القرائية (`public_api.py` — `/api/v1/*` + `OpenAPI 3.1.0`):**
   - نقاط نهاية ثابتة ومحدّثة كل 30 دقيقة على فرع `@data` (`/api/v1/{health,statistics,servers,countries,protocols,sources,openapi}.json`) + خادم HTTP محلي يدعم الترقيم، الفلترة، `ETag/304`، وتحديد المعدّل (`429 Token Bucket`) مع تعمية كاملة للروابط الخام وعناوين IP.
3. **لوحة تحكم الويب المعيارية (17 صفحة) + لوحة المراقبة العامة (`web-admin/` على `GitHub Pages`):**
   - **`index.html`**: 17 صفحة إدارة مشفّرة عبر **WebCrypto** مباشرة مع `api.github.com` لإدارة المشتركين والباقات والأجهزة وعقد `VIP 💎` والتقارير (`CSV/Excel` و`PDF`).
   - **`monitor.html`**: لوحة مراقبة حيّة عامة ثنائية اللغة (عربي `RTL` / إنجليزي `LTR`) بالوضعين الداكن والفاتح مع تخزين مؤقت `60s` ومخططات اتجاهات تاريخية `SVG` وصفر أسرار.
4. **قاعدة البيانات المؤسسية من 24 جدولًا وتطبيق المشرف المستقل (`Admin APK v3.2` — `2.19 MB`):**
   - خزنة SQLite علائقية (`enterprise/migrations/001..003`) بحسابات `Argon2id`، توثيق ثنائي `TOTP 2FA`، سجل تدقيق متسلسل ببصمات `SHA-256`، نسخ احتياطي مشفّر (`AES-256-GCM`)، وتطبيق مشرف مستقل يوقّع وينشر `enterprise/bundle.json` من الهاتف مباشرة.

---

## 3) القوائم السحابية المتخصّصة ونقاط نهاية `API v1` (تتحدّث آليًا كل 30 دقيقة على فرع `@data`)

جميع قوائم الاشتراك متوافقة مع تطبيق `bahrain-vpn` وكذلك `v2rayNG` و`Hiddify` و`Streisand` و`Shadowrocket` و`NekoBox` (عُقد `VIP 💎` المشفّرة معزولة داخل `enterprise/bundle.json` ولا تُنشر في القوائم العامة):

| الملف | الوصف | الرابط المباشر (`jsDelivr CDN`) |
|---|---|---|
| **`sub.txt`** | اشتراك `Base64` الشامل لجميع العُقد العامة الحيّة بوسم `bahrain-vpn` | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/sub.txt` |
| **`best100.txt`** | أفضل 100 عقدة مرتّبة بالدرجة المركّبة مع تنويع المضيفين والشبكات الفرعية (`/24`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/best100.txt` |
| **`privacy_aware.txt`** | الأعلى أمانًا في طبقة النقل (`Verified TLS/Reality` فقط وبدون `allowInsecure`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/privacy_aware.txt` |
| **`reliable.txt`** / **`reliable_sub.txt`** | الأعلى استقرارًا واعتمادية عبر الجولات المتتالية (نصي + `Base64`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/reliable_sub.txt` |
| **`low_latency.txt`** | الأقلّ زمن استجابة وتذبذبًا (`Median RTT + Jitter`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/low_latency.txt` |
| **`high_throughput.txt`** | الأعلى سرعة تنزيل موثّقة عبر النفق الفعلي | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/high_throughput.txt` |
| **`protocols/*.txt`** | قوائم مفصولة حسب البروتوكول (`vless`, `trojan`, `vmess`, `ss`, `hysteria2`, `tuic`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/protocols/vless.txt` |
| **`alive.json`** | البيانات الكاملة للعُقد الحيّة مع التقييم الأمني متعدد الأبعاد والدولة والاستقرار | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/alive.json` |
| **`api/v1/statistics.json`** | واجهة الإحصاءات العامة المعماة (`v1`) ومواصفة `api/v1/openapi.json` | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/api/v1/statistics.json` |
| **`api/v1/health.json`** | نبضة صحة خط الأنابيب السحابي وحالة الحداثة | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/api/v1/health.json` |
| **`quarantined.json`** | سجل الحجر الصحي الأمني المعزول (معرّفات معماة وأسباب الرفض دون تسريب روابط) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/quarantined.json` |
| **`enterprise/bundle.json`** | حزمة التراخيص الموقّعة (`ECDSA P-256` — `v3.2`)، الإعدادات البعيدة، التحديثات، وعُقد `VIP` المشفّرة | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/enterprise/bundle.json` |
| **`promo/ads.json`** | توصيف البطاقات الترويجية الخمس الدوّارة والصور المرافقة (`ad1.png..ad5.png`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/promo/ads.json` |
| **`countries.json`** | توزيع العُقد الحيّة حسب دولة الخروج مع مصدر الثقة (`exit_trace` مقابل `remark_hint`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/countries.json` |
| **`source_health.json`** | تقرير صحّة المصادر، العزل التلقائي، التداخل، والإضافة الحصرية (خالٍ من الأسرار) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/source_health.json` |
| **`all.txt.gz`** | المجمّع البنيوي النظيف الكامل مضغوطًا قبل الفحص | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/all.txt.gz` |
| **`meta.json`** | ملخص الدورة الشامل ومؤشرات الصحّة والأمان (`security_summary`, `risk_summary`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/meta.json` |

---

## 4) الهيكل الهندسي للمستودع والملفات الرئيسية

| المسار | الوظيفة الهندسية |
|---|---|
| `pipeline_security.py` | حراسة SSRF وفحص التحويلات، منع الشبكات الخاصة وواجهات Metadata، التحقق من بصمات `SHA-256`، فك الضغط الآمن ضد `Zip/Tar-Slip`، وحجب الأسرار من السجلات |
| `security_intelligence.py` | محرك تقييم الأمان والخصوصية المستقل عن السرعة (`SecurityReport`, `MultiDimensionalScore`) وسجل الحجر الصحي (`QuarantineRegistry`) |
| `public_api.py` | مصدّر وخادم واجهة الإحصاءات العامة القرائية (`/api/v1/*` + `OpenAPI 3.1.0` + `ETag/304` + `TokenBucketRateLimiter` + `state/pipeline_history.json`) |
| `dedupe.py` | إزالة التكرار خماسية الطبقات (المطابقة الخام ← الهوية البروتوكولية المعيارية ← تتبّع المصدر ← تجميع `/24` و`/48` ← تنويع المخرجات) |
| `scoring.py` | التقييم المركّب متعدد الأبعاد و5 ملفات ترتيب (`BALANCED`, `LOW_LATENCY`, `HIGH_SPEED`, `HIGH_RELIABILITY`, `PRIVACY_AWARE`)، سجل `NodeHistoryStore`، وعزل المصادر التالفة |
| `collector.py` / `tester.py` | الجلب المتوازي المحصّن بـ `ETag/Last-Modified` وبصمة `SHA-256` لـ 277 قناة تلغرام و26 تغذية GitHub + فحص النفق عبر `Xray-core` و`sing-box` |
| `server/build_data.py` | منسّق دورة البناء السحابية، الحجر الصحي قبل/بعد الفحص، تصدير `/api/v1/*`، وحماية آخر نسخة صالحة (`Last-Known-Good Fallback`) |
| `enterprise/` | نواة المنصة المؤسسية `v3.2` (`database.py` لـ 24 جدولًا و`migrations/001..003`، `crypto_security.py`، `ai_intelligence.py`، `publisher.py`) |
| `web-admin/` | لوحة التحكم الويب المعيارية من 17 صفحة (`index.html`, `app.js`, `modules/*.js`) + لوحة المراقبة الحيّة العامة (`monitor.html`, `monitor.js`) |
| `android/app/` | تطبيق المشترك `v3.2` (`vpn/{BahrainVpnService,LeakProtectionEngine,KillSwitchController,BootRestoreReceiver,SmartFailoverEngine,VpnState}.kt`، `engine/{SingBox,SecurityEvaluator,ServerRanker}.kt`، `enterprise/`، `ui/`) |
| `android/admin/` | تطبيق المشرف المستقل `v3.2` (`AdminMainActivity.kt`، `AdminGitHubEngine.kt`، وقواعد تقليص `R8`) |
| `promo/` | نظام البطاقات الإعلانية الدوّارة الخمس (`ads.json` + `ad1.png..ad5.png`) |
| `.github/workflows/` | مسارات الأتمتة الأربع المثبّتة ببصمات `40-char SHA` وبأقل صلاحيات (`ci.yml`, `data.yml`, `enterprise.yml`, `apk.yml`) |

---

## 5) التشغيل اليدوي، النشر المؤسسي، والاختبارات الآلية (CLI)

```bash
pip install -r requirements.txt

# 1. جمع وفحص العُقد السحابية وبناء قوائم dist/ و api/v1/
python collector.py                              # جمع وتنظيف وتسمية bahrain-vpn ← config.txt
python collector.py --test                       # جمع + فحص متعدد الجولات + أفضل 100 ← best.txt
python tester.py -i config.txt --best 100        # فحص ملف محلي وترتيب الأفضل
TEST_TOP=400 python server/build_data.py         # تشغيل دورة الخادم محليًا ← dist/ + dist/api/v1/
python public_api.py --dist dist --port 8080     # تشغيل خادم واجهة الإحصاءات العامة v1 محليًا

# 2. توليد حزمة التراخيص الموقّعة (bundle.json v3.2) والنسخ الاحتياطي المشفّر
ENTERPRISE_MASTER_KEY="your-strong-passphrase" python -m enterprise.publisher \
  --vault enterprise/vault/enterprise_vault.enc.json \
  --alive dist/alive.json \
  --bundle-out dist/enterprise/bundle.json \
  --backup-dir dist/enterprise/backups

# 3. التحقق من لوحتَي الويب والمراقبة وتشغيل حزمة الاختبارات الشاملة (42 اختبار pytest)
for jsf in web-admin/*.js web-admin/modules/*.js; do node --check "$jsf"; done
pytest -v
```

- **تفعيل لوحتَي الإدارة والمراقبة على GitHub Pages:** ينشر سير عمل `.github/workflows/enterprise.yml` ملفات `web-admin/` تلقائيًا إلى فرع `gh-pages`؛ من إعدادات المستودع (`Settings -> Pages`) اختر الفرع `gh-pages` والمجلد `/ (root)`:
  - لوحة الإدارة المشفّرة: `https://oldman-552.github.io/vpn-configs/`
  - لوحة المراقبة الحيّة العامة: `https://oldman-552.github.io/vpn-configs/monitor.html`
- **الاختبارات الآلية المستمرة:**
  - **`42/42` اختبار `pytest`** (`tests/test_all.py` + `tests/test_enterprise_platform.py` + `tests/test_security_ranking_and_api.py`) تغطي أمن خط الأنابيب، فصل الأمان عن السرعة، الحجر الصحي، ملفات الترتيب الخمسة، عزل المصادر، التشفير المؤسسي، وواجهة `API v1`.
  - **`19/19` اختبار `JUnit / Robolectric`** (`:app` + `:admin` شاملةً `AndroidVpnAuditTest`، `EnterpriseAndroidTest`، `LeakKillSwitchAndSecurityTest`، و`AdminAppUnitTest`) تغطي منع تسرب `DNS/IPv6`، مفتاح الإيقاف الصارم، حالات النفق الثمان، التبديل الاستباقي، والتحقق الرقمي `ECDSA P-256`.

---

## 6) التوثيق الهندسي المرجعي الكامل والقيود الأمنية الصريحة

- البنية المعمارية الشاملة (`v3.2`): [`ARCHITECTURE.md`](ARCHITECTURE.md) | [`docs/ENTERPRISE_ARCHITECTURE_AND_OPERATIONS.md`](docs/ENTERPRISE_ARCHITECTURE_AND_OPERATIONS.md)
- الأمن والخصوصية ونموذج التهديدات: [`SECURITY.md`](SECURITY.md) | [`PRIVACY.md`](PRIVACY.md)
- توثيق واجهة الإحصاءات العامة (`API v1` + `OpenAPI 3.1.0`): [`API.md`](API.md)
- النشر والتشغيل والاختبارات واستكشاف الأخطاء: [`DEPLOYMENT.md`](DEPLOYMENT.md) | [`TESTING.md`](TESTING.md) | [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) | [`CHANGELOG.md`](CHANGELOG.md)
- تقارير المراجعة الهندسية الشاملة (Phase 1 Audit): [`ARCHITECTURE_AUDIT.md`](ARCHITECTURE_AUDIT.md) | [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) | [`PERFORMANCE_AUDIT.md`](PERFORMANCE_AUDIT.md) | [`IMPROVEMENT_ROADMAP.md`](IMPROVEMENT_ROADMAP.md)
- منهجية اختيار المصادر ونتائج قياس التفرّد والتداخل: [`sources.md`](sources.md) | [`review.md`](review.md)
- **التزام الخصوصية الصارم:** لا يسجّل التطبيق ولا المنصة أي سجل تصفح، عناوين مواقع يزورها المستخدم، كلمات مرور، رسائل، أو محتوى حزم الشبكة (`Zero Traffic Sniffing`).
- **الشفافية الأمنية الصارمة:** يفصل المحرك الأمني كليًا بين سرعة السيرفر وأمان تشفيره، ولا يمنح العُقد العامة المجهولة صفة `Privacy: Verified` أبدًا (تُمنح فقط لعُقد `VIP 💎` الخاصة الموثّقة). كما يوضّح التطبيق بصراحة حدود نظام أندرويد (لحظات الإقلاع الأولى قبل تشغيل التطبيق تتطلب تفعيل `Always-On VPN + Lockdown` من إعدادات النظام).
