# bahrain-vpn — منصة ULTIMATE VPN ENTERPRISE `v1` الرسمية المتكاملة

[![Release](https://img.shields.io/badge/Release-v1%20(Official)-success?style=for-the-badge)](https://github.com/oldman-552/vpn-configs/releases/tag/v1)
[![Languages](https://img.shields.io/badge/APK%20Languages-Arabic%20(Primary)%20%2B%20English-0ea5e9?style=for-the-badge)](android/README.md)
[![Architecture](https://img.shields.io/badge/Architecture-Central%20Top%20500%20%2B%20Local%20Top%2050-blue?style=for-the-badge)](docs/ANDROID_ARCHITECTURE.md)
[![Play Protect](https://img.shields.io/badge/Play%20Protect-Zero%20Dropper%20%2B%20RSA--4096%20v2%2Fv3-brightgreen?style=for-the-badge)](SECURITY.md)
[![Infrastructure](https://img.shields.io/badge/100%25%20GitHub-Zero%20External%20VPS-24292f?style=for-the-badge)](DEPLOYMENT.md)

منظومة VPN مؤسسية وسحابية متكاملة تعمل آليًا بالكامل **100% داخل بيئة GitHub دون أي خوادم خارجية (`Zero VPS / Zero Third-Party Cloud`)** تحت الهوية الموحّدة **`bahrain-vpn`** والإصدار الرسمي المعتمد **`v1`**:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                          منظومة ULTIMATE VPN ENTERPRISE v1 (Pure-GitHub)                         │
├────────────────────────────────────────────────┬─────────────────────────────────────────────────┤
│ 1) قاعدة بيانات GitHub المركزية (Top 500)      │ 2) تطبيق المشترك الذكي للأندرويد (User APK v1)  │
│ • 277 قناة تلغرام + 26 تغذية GitHub منتقاة     │ • ثنائي اللغة: العربية أساسية (RTL) + الإنجليزية│
│ • فحص بنيوي + إزالة تكرار 5 طبقات + حجر صحي    │ • استثناء تلقائي لنطاقات .ir مباشرة (زر تحكم)  │
│ • اختيار حتى 500 مرشح مؤهّل فقط بدون أي حشو    │ • هوتسبوت VPN بدون روت (HTTP/SOCKS5/PAC آمن)    │
│ • قوائم إيران والدول الموثّقة مجتمعيًا (IR)    │ • فحص مجتمعي طوعي موثّق + Top 50 محلي لكل شبكة  │
│ • قاعدة ذكاء تاريخي SQLite (24h/7d/30d/90d)     │ • متوافق مع Play Protect (Zero Dropper + v2/v3) │
│   + واجهة إحصاءات عامة (/api/v1/* + OAS 3.1)   │   + منع تسرب DNS/IPv6 + Kill Switch + عقد VIP💎 │
├────────────────────────────────────────────────┼─────────────────────────────────────────────────┤
│ 3) تطبيق المشرف المستقل (Admin APK v1)         │ 4) لوحة الإدارة + شاشة المراقبة الحيّة (Web v1)  │
│ • ثنائي اللغة: العربية أساسية (RTL) + الإنجليزية│ • 17 صفحة إدارة مشفّرة (index.html على Pages)   │
│ • موقّعة بشهادة إصدار RSA-4096 APK v2/v3       │ • لوحة مراقبة حيّة عامة (monitor.html AR/EN)    │
│ • توثيق ثنائي TOTP 2FA + خزنة AES-256-GCM      │ • مؤشر Central Candidate Pool (Top 500) الحي    │
│ • إدارة المشتركين والأجهزة وعقد VIP المشفّرة    │ • تشفير متصفح أصيل WebCrypto بدون خادم وسيط     │
│ • توقيع ECDSA P-256 ومزامنة عبر api.github     │ • مخططات تاريخية 24h/7d/30d/90d وتقارير شاملة   │
└────────────────────────────────────────────────┴─────────────────────────────────────────────────┘
```

---

## 1) التحميل المباشر للإصدار الرسمي `v1` (`Latest`) والتحقق الأمني

جميع حزم الإصدار الرسمي **`v1`** (`versionName = "1.0"`, `versionCode = 1`) مبنية وموقّعة آليًا عبر مسار `.github/workflows/apk.yml` بشهادة إصدار **`RSA-4096` (`APK Signature Scheme v1 + v2 + v3` — بدون شهادة `Android Debug`)**، وتدعم **اللغة العربية كلغة أساسية افتراضية (`RTL`) مع دعم كامل للغة الإنجليزية (`LTR`) وتبديل فوري بضغطة واحدة**، ومحصّنة للتوافق مع **Google Play Protect** (خالية تمامًا من صلاحية `REQUEST_INSTALL_PACKAGES` وسلوك `Dropper`)، مع تقليص الحجم عبر **`R8 + Resource Shrinking`**:

- **صفحة الإصدار الرسمي الموقّع:** [**GitHub Releases — `bahrain-vpn v1` (`Latest`)**](https://github.com/oldman-552/vpn-configs/releases/tag/v1)

| الحزمة الرسمية (`v1`) | الاستخدام الموصى به | معرّف النسخة | اللغات المدعومة | رابط التحميل المباشر (`HTTPS`) |
|---|---|---|---|---|
| **`app-arm64-v8a-release.apk`** | **تطبيق المشترك** لجميع هواتف أندرويد الحديثة (`ARM64`) | `versionCode = 1` (`v1`) | العربية (أساسية) + English | [تحميل ARM64 v1](https://github.com/oldman-552/vpn-configs/releases/download/v1/app-arm64-v8a-release.apk) |
| **`app-x86_64-release.apk`** | **تطبيق المشترك** لأجهزة ومحاكيات `x86_64` | `versionCode = 1` (`v1`) | العربية (أساسية) + English | [تحميل x86_64 v1](https://github.com/oldman-552/vpn-configs/releases/download/v1/app-x86_64-release.apk) |
| **`app-release.apk`** | **تطبيق المشترك الشامل** (`Universal`: يضم كل المعماريات) | `versionCode = 1` (`v1`) | العربية (أساسية) + English | [تحميل Universal v1](https://github.com/oldman-552/vpn-configs/releases/download/v1/app-release.apk) |
| **`app-admin-release.apk`** | **تطبيق المشرف المستقل** (`com.bahrain.vpnadmin`) | `versionCode = 1` (`v1`) | العربية (أساسية) + English | [تحميل Admin v1](https://github.com/oldman-552/vpn-configs/releases/download/v1/app-admin-release.apk) |
| **`SHA256SUMS.txt`** | ملف البصمات التشفيرية المجمّع (`SHA-256`) لجميع الحزم الموقّعة في الإصدار الرسمي `v1` | `v1` (`1.0`) | — | [تحميل SHA256SUMS.txt](https://github.com/oldman-552/vpn-configs/releases/download/v1/SHA256SUMS.txt) |

---

## 2) المعمارية الهندسية والأمنية في الإصدار الرسمي `v1`

### أ) واجهة ثنائية اللغة (العربية أساسية `RTL` + الإنجليزية `LTR`) وتوجيه مباشر لنطاقات `.ir`
1. **اللغة العربية هي اللغة الأساسية والافتراضية:** يعمل كل من تطبيق المشترك (`com.bahrain.vpnconfigs`) وتطبيق المشرف (`com.bahrain.vpnadmin`) باللغة العربية وتخطيط `RTL` افتراضيًا عند التثبيت الأول (`Prefs.appLanguage = "ar"` + `res/xml/locales_config.xml`).
2. **تبديل فوري كامل إلى الإنجليزية (`EN`):** يمكن التبديل الفوري بين **العربية** و**الإنجليزية** بضغطة واحدة من الشريط العلوي (`EN / عربي`) أو من شاشة الإعدادات دون إعادة تشغيل التطبيق، مع تحديث لحظي لاتجاه الواجهة (`RTL ↔ LTR`) وجميع الشاشات والإشعارات وزر شريط الإعدادات السريعة (`Quick Settings Tile`).
3. **استثناء تلقائي لنطاقات `.ir` و `.ایران` من الـ VPN (مفعّل افتراضياً + زر تحكم في الإعدادات):**
   - أي اتصال لدومين أو سيرفر ينتهي بـ **`.ir`** أو **`.ایران`** (`.xn--mgba3a4f16a`) يخرج **مباشرة عبر إنترنت الجهاز الأصلي (`direct` + `direct-dns` + `TLS SNI sniff`)** دون المرور على سيرفر الـ VPN، مع وجود زر تحكم فوري بتفعيله أو إيقافه داخل **الإعدادات** وداخل شاشة **استثناء التطبيقات**.

### ب) الفصل الصارم بين GitHub (`Top 500`) وتطبيق Android (`Personalized Top 50`)
1. **مسؤولية GitHub (قاعدة المرشّحات المركزية — `central_top500.py`):**
   - `Collect → Validate → Normalize → Deduplicate → Assign server_id & config_fingerprint → Preliminary Check → Rank Centrally → Publish up to 500`
   - ينشر **بحد أقصى 500 سيرفر مؤهّل فقط** في `top500.json` و`top500.txt` و`top500.manifest.json` و`top500.delta.json` دون أي حشو أو اختلاق، ويصرّح رسميًا بـ `"personalized_top50_authority": "ANDROID_LOCAL_ONLY"` و`"trust_posture": "UNTRUSTED_PUBLIC_SERVER"`.
2. **مسؤولية Android الحصرية (الذكاء المحلي المخصّص — `LocalServerIntelligence.kt` + `ClientDatabase.kt`):**
   - **تزامن محصّن (`Repo.syncTop500Dataset`):** يدعم `ETag / 304 Not Modified`، التحديث التفاضلي `top500.delta.json`، التحقق التشفيري المزدوج `SHA-256`، منع التراجع `Rollback Protection`، والاستعادة التلقائية لآخر نسخة صالحة `top500.last_valid.json`.
   - **الفحص التسلسلي عبر النفق الحقيقي (`SequentialTunnelScanner`, `concurrency = 1`):** يختبر نفقًا واحدًا فقط في كل لحظة عبر `Mutex` تسلسلي، ويقيس زمن التأسيس `establishMs`، التأخير الفعلي `latencyMs`، التذبذب `jitterMs`، فقدان الحزم `packetLossPct`، سرعة التنزيل `throughputKbps`، والاستقرار `stabilityScore`.
   - **وضعان ذكيان للفحص:**
     - **فحص سريع (`Quick Scan`):** يختبر `TOP_50` الناجحة مؤخرًا بالترتيب (`#1, #2...`) ثم الاحتياطي عند الحاجة، ويتوقف مبكرًا فور توفر عدد كافٍ من السيرفرات المؤهّلة توفيرًا للبطارية وبيانات الجوال.
     - **فحص شامل (`Full Scan`):** يقيّم كامل حزمة الـ `Top 500` بالتسلسل لاكتشاف السيرفرات الأسرع وتحديث `TOP_50` ومجمّع `BACKUP_POOL`.
   - **عزل تام حسب الشبكة (`WIFI` مقابل `MOBILE_DATA`):** ترتيب `TOP_50` ومجمّع الاحتياطي والسجل التاريخي التراكمي (`Append-Only`) منفصلة كليًا لكل نوع شبكة.

### ج) التوافق الأمني مع Google Play Protect والتوقيع الرسمي (`v1`)
1. **إزالة بصمة المحمّلات (`Zero Dropper Behavior`):**
   - خالٍ تمامًا من صلاحية `android.permission.REQUEST_INSTALL_PACKAGES` ومن أي تنزيل داخلي لملفات `.apk` أو استدعاء `"application/vnd.android.package-archive"`.
   - يفوّض `AppUpdateManager` تحميل الحزمة المناسبة لمعمارية المعالج (`arm64-v8a` / `x86_64` / `universal`) إلى المتصفح الرسمي للنظام حصريًا عبر روابط `HTTPS` الموثّقة في `enterprise/bundle.json` مع نسخ بصمة `SHA-256` للحافظة.
2. **توقيع الإصدار الرسمي (`RSA-4096 PKCS12` + `APK Signature Scheme v1 / v2 / v3`):**
   - يوقّع `.github/workflows/apk.yml` حزم المشترك والمشرف بشهادة إصدار `RSA-4096` تدعم مخططات التوقيع `v1 + v2 + v3` ويتحقق آليًا عبر `apksigner` من غياب شهادة `CN=Android Debug` ومن غياب `REQUEST_INSTALL_PACKAGES`.
   - يدعم ربط شهادة إنتاج ثابتة خاصة بك عبر أسرار المستودع (`KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`) لتراكم سمعة التوقيع عبر الإصدارات القادمة.

### د) مشاركة الـ VPN عبر الهوتسبوت بدون روت (`Rootless VPN Hotspot`) والفحص المجتمعي الموثّق لإيران (`IR`)
1. **مشاركة اتصال الـ VPN عبر الهوتسبوت بدون روت (`VpnHotspotManager.kt` + `VpnHotspotScreen.kt`):**
   - واجهة مستقلة (`نقطة اتصال الـ VPN / VPN Hotspot`) تميّز بصدق تام بين **`الوضع A: توجيه نظام كامل موثّق`**، و**`الوضع B: مشاركة عبر بروكسي الشبكة المحلية بدون روت`** (مستمع محلي مربوط حصريًا بعنوان الشبكة الخاصة مثل `192.168.43.1` يقدّم `HTTP/HTTPS CONNECT` + `SOCKS5 TCP/UDP` + ملف إعداد تلقائي `/proxy.pac` + مصادقة اختيارية باسم مستخدم وكلمة مرور)، و**`الوضع C: غير متاح`**.
   - **حماية إغلاق آمن صارمة (`Fail-Closed`):** مستحيل أن يستمع على `0.0.0.0` أو الشبكة العامة، وعند انقطاع نفق الـ VPN تُغلق جميع الجلسات فورًا (`HTTP 503` / قطع التدفقات) دون تمرير أي حزمة إلى الإنترنت غير المحمي أبدًا.
2. **الفحص المجتمعي الطوعي وترتيب سيرفرات إيران الموثّقة (`CommunityTestingManager.kt` + `community_ranking.py`):**
   - **طوعي 100% ومعطّل افتراضيًا (`OFF by default`):** يتطلب موافقة صريحة مع زر إلغاء فوري وتدوير المعرّف العشوائي؛ يُجري الهاتف فحصًا تسلسليًا محليًا فقط (`127.0.0.1`) عبر بروتوكولات `VLESS / VMess / Trojan / Shadowsocks / Hysteria2 / TUIC / SOCKS5 / HTTP(S)` **ولا يعمل أبدًا كبروكسي عام أو نقطة عبور**، ولا يعمل أثناء اتصال الـ VPN أو تشغيل `VPN Hotspot`.
   - **تحقق صادق من الشبكة الإيرانية (`IR`) ومقاومة التلاعب:** يتحقق من غياب أي `TRANSPORT_VPN` ومن عنوان الخروج المباشر (وعبر حافة `Cloudflare Worker + D1` المجانية عند تفعيلها)، ويشترط تأكيد **جهازين مستقلين على الأقل (`min_distinct_reporters = 2`)** مع حساب الوسيط (`Median Latency/Speed`) وتناقص الحداثة وعزل نتائج `IR` في `iran-top500.json` و`iran-top500.txt` و`iran-results.json`.

### هـ) منع تسرب `DNS/IPv6`، مفتاح الإيقاف الصارم، والذكاء التاريخي
- **عزل `DNS` و`IPv6` (`LeakProtectionEngine`):** توجيه `tunnel-dns` إجباريًا داخل النفق (`detour="proxy"`) والتقاط المسار `::/0` دائمًا داخل واجهة `tun0`.
- **مفتاح الإيقاف من مستويين (`KillSwitchController` + `ConnectionSecurityClassifier`):** فصل صريح وصادق بين حجب `tun0` على مستوى التطبيق (`PROTECTION_ACTIVE`) وبين قفل النظام الكامل (`OS Always-On VPN Lockdown` عبر `VpnService.isLockdownEnabled`) ضمن 9 حالات أمان موثّقة.
- **قاعدة الذكاء التاريخي السحابية (`historical_db.py` — `state/history.sqlite3`):** تحليلات جاهزية وأداء نافذية (`24h/7d/30d/90d`) بأساس صريح (`OBSERVED / ESTIMATED / UNKNOWN`)، وعزل مشغّلي المصادر المستقلين، و10 فئات لتشخيص الأعطال.
- **المنصة المؤسسية وعُقد `VIP 💎` المشفّرة (`AES-256-GCM` + `ECDSA P-256`):** 17 صفحة إدارة مشفّرة عبر `WebCrypto` (`web-admin/index.html`) + لوحة رصد حيّة عامة (`web-admin/monitor.html`) + تطبيق مشرف مستقل (`app-admin-release.apk`).

---

## 3) القوائم السحابية المتخصّصة وحزمة `Top 500` ونقاط `API v1` (تتحدّث كل 30 دقيقة على فرع `@data`)

| الملف | الوصف الهندسي | الرابط المباشر (`jsDelivr CDN`) |
|---|---|---|
| **`top500.manifest.json`** | بيان الإصدار وبصمات `SHA-256` وحالة التحديث التفاضلي لحزمة المرشّحات المركزية | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/top500.manifest.json` |
| **`top500.json`** | حزمة المرشّحات المركزية المؤهّلة (حتى 500 سيرفر بدون حشو — اختيار الـ `Top 50` محلي على أندرويد فقط) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/top500.json` |
| **`top500.delta.json`** | ملف التحديث التفاضلي بين آخر إصدارين لحزمة `Top 500` لتوفير استهلاك البيانات | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/top500.delta.json` |
| **`top500.txt`** | الروابط الخام المطبّعة لحزمة المرشّحات المركزية `Top 500` | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/top500.txt` |
| **`iran-top500.json`** | قائمة السيرفرات الموثّقة مجتمعيًا من داخل شبكات إيران المباشرة (`IR` — تقييم متعدد الأجهزة بدون حشو) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/iran-top500.json` |
| **`iran-top500.txt`** | الروابط الخام المطبّعة لقائمة سيرفرات إيران الموثّقة مجتمعيًا (`IR`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/iran-top500.txt` |
| **`iran-results.json`** | السجل التحليلي المعمّى لقياسات الفحص المجتمعي الموثّق من داخل إيران (`IR`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/iran-results.json` |
| **`sub.txt`** | اشتراك `Base64` الشامل لجميع العُقد العامة الحيّة بوسم `bahrain-vpn` | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/sub.txt` |
| **`best100.txt`** | أفضل 100 عقدة مرتّبة بالدرجة المركّبة مع تنويع المضيفين والشبكات الفرعية (`/24`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/best100.txt` |
| **`privacy_aware.txt`** | الأعلى أمانًا في طبقة النقل (`Verified TLS/Reality` فقط وبدون `allowInsecure`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/privacy_aware.txt` |
| **`reliable.txt`** / **`reliable_sub.txt`** | الأعلى استقرارًا واعتمادية عبر الجولات المتتالية (نصي + `Base64`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/reliable_sub.txt` |
| **`low_latency.txt`** | الأقلّ زمن استجابة وتذبذبًا (`Median RTT + Jitter`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/low_latency.txt` |
| **`high_throughput.txt`** | الأعلى سرعة تنزيل موثّقة عبر النفق الفعلي | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/high_throughput.txt` |
| **`alive.json`** | البيانات الكاملة للعُقد الحيّة مع التقييم الأمني متعدد الأبعاد والدولة والاستقرار | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/alive.json` |
| **`servers-current.json`** | الحالة الحالية لجميع السيرفرات بهويات `server_id` معماة خالية من بيانات الاعتماد | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/servers-current.json` |
| **`servers-history.json`** | السجل التاريخي للجاهزية (`24h/7d/30d/90d`) بأساس صريح (`OBSERVED/ESTIMATED/UNKNOWN`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/servers-history.json` |
| **`servers-performance.json`** | تحليلات الأداء النافذية (`avg/median/p95` للتأخير، التذبذب، فقدان الحزم، والسرعة) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/servers-performance.json` |
| **`servers-statistics.json`** | الإحصاءات الشاملة والجاهزية وفئات الأعطال الـ 10 (`countries-statistics.json` / `sources-statistics.json`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/servers-statistics.json` |
| **`api/v1/statistics.json`** | واجهة الإحصاءات العامة المعماة (`v1`) ومواصفة `api/v1/openapi.json` | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/api/v1/statistics.json` |
| **`enterprise/bundle.json`** | حزمة التراخيص الموقّعة (`ECDSA P-256` — `v1` / `"1.0"`)، التحديثات، وعُقد `VIP` المشفّرة | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/enterprise/bundle.json` |
| **`promo/ads.json`** | توصيف البطاقات الترويجية الخمس الدوّارة والصور المرافقة (`ad1.png..ad5.png`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/promo/ads.json` |
| **`meta.json`** | ملخص الدورة الشامل ومؤشرات الصحّة والأمان (`top500_qualified`, `security_summary`) | `https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/meta.json` |

---

## 4) الهيكل الهندسي للمستودع والملفات الرئيسية (`v1`)

| المسار | الوظيفة الهندسية |
|---|---|
| `central_top500.py` | محرك اختيار وتصدير حزمة المرشّحات المركزية (`Top 500` بدون حشو) مع بصمات `SHA-256` وفرق `top500.delta.json` |
| `community_ranking.py` / `community-worker/` | محرك التقييم المجتمعي متعدد الأجهزة المقاوم للتلاعب (`iran-top500.{json,txt}`, `iran-results.json`, وقوائم الدول) + بوابة الاستقبال المجانية (`Cloudflare Worker + D1`) |
| `historical_db.py` | قاعدة بيانات الذكاء التاريخي `SQLite` (`migrations/history/001..002.sql`) وتحليلات `24h/7d/30d/90d` |
| `pipeline_security.py` / `security_intelligence.py` | حراسة SSRF، التحقق من بصمات `SHA-256`، تقييم الأمان المستقل عن السرعة، وسجل الحجر الصحي (`QuarantineRegistry`) |
| `dedupe.py` / `scoring.py` | إزالة التكرار خماسية الطبقات والهوية المعماة `server_id` + التقييم متعدد الأبعاد و5 ملفات ترتيب |
| `collector.py` / `tester.py` / `server/build_data.py` | الجلب المحصّن بـ `ETag` لـ 277 قناة تلغرام و26 تغذية GitHub + فحص النفق عبر `Xray-core` و`sing-box` + حماية `Last-Known-Good` |
| `public_api.py` | مصدّر وخادم واجهة الإحصاءات العامة القرائية (`/api/v1/*` + `OpenAPI 3.1.0` + `ETag/304`) |
| `enterprise/` | نواة المنصة المؤسسية `v1` (`database.py`, `crypto_security.py`, `ai_intelligence.py`, `publisher.py`) |
| `web-admin/` | لوحة التحكم الويب المعيارية من 17 صفحة (`index.html`) + لوحة المراقبة الحيّة العامة (`monitor.html`) بإصدار `v1` |
| `android/app/` | تطبيق المشترك الرسمي `v1` (`versionCode = 1`, `versionName = "1.0"`): ثنائي اللغة `AR` أساسية + `EN` (`AppI18n.kt`)، `LocalServerIntelligence.kt`، `ClientDatabase.kt`، `AppUpdateManager.kt`، `BahrainVpnService.kt`، `LeakProtectionEngine.kt`، `KillSwitchController.kt`، `ConnectionSecurityClassifier.kt` |
| `android/admin/` | تطبيق المشرف المستقل `v1` (`versionCode = 1`, `versionName = "1.0"`): ثنائي اللغة `AR` أساسية + `EN`، `AdminMainActivity.kt`، `AdminGitHubEngine.kt`، وتوقيع `RSA-4096 v1/v2/v3` |
| `.github/workflows/` | مسارات الأتمتة الأربع المثبّتة ببصمات `40-char SHA` (`ci.yml`, `data.yml`, `enterprise.yml`, `apk.yml`) |

---

## 5) تثبيت مفتاح توقيع دائم خاص بك (`Release Keystore`) لتوثيق Play Protect

يدعم `.github/workflows/apk.yml` تلقائيًا التوقيع بمفتاح إنتاج ثابت خاص بك عبر **GitHub Actions Secrets** لضمان ثبات بصمة الشهادة عبر جميع الإصدارات القادمة وتوثيقها لدى Google Play Protect:

```bash
# 1. توليد مفتاح توقيع إنتاج دائم مرة واحدة فقط على جهازك الشخصي (احتفظ به في مكان آمن)
keytool -genkeypair -v -storetype PKCS12 -keystore bahrain-vpn-release.p12 \
  -alias bahrain_vpn_release -keyalg RSA -keysize 4096 -sigalg SHA256withRSA -validity 9125 \
  -dname "CN=Bahrain VPN Official, OU=Security, O=Bahrain VPN, L=Manama, C=BH"

# 2. تحويل المفتاح إلى Base64 لإضافته في Settings -> Secrets and variables -> Actions:
base64 -w0 bahrain-vpn-release.p12
# أضف الأسرار الأربعة التالية في إعدادات مستودع GitHub:
#   KEYSTORE_BASE64   = ناتج الأمر أعلاه
#   KEYSTORE_PASSWORD = كلمة مرور ملف الـ Keystore
#   KEY_ALIAS         = bahrain_vpn_release
#   KEY_PASSWORD      = كلمة مرور المفتاح
```

---

## 6) التشغيل اليدوي والاختبارات الآلية الشاملة (`v1`)

```bash
pip install -r requirements.txt

# 1. جمع وفحص العُقد السحابية وبناء قوائم dist/ شاملةً top500.* و servers-*.json و api/v1/
TEST_TOP=400 python server/build_data.py

# 2. توليد حزمة التراخيص الموقّعة (bundle.json v1)
ENTERPRISE_MASTER_KEY="your-strong-passphrase" python -m enterprise.publisher \
  --vault enterprise/vault/enterprise_vault.enc.json \
  --alive dist/alive.json \
  --bundle-out dist/enterprise/bundle.json \
  --backup-dir dist/enterprise/backups

# 3. التحقق من لوحتَي الويب والمراقبة وتشغيل حزمة الاختبارات الشاملة (51 اختبار pytest)
for jsf in web-admin/*.js web-admin/modules/*.js; do node --check "$jsf"; done
pytest -v
```

- **تغطية الاختبارات الآلية المستمرة (`CI Green`):**
  - **`54/54` اختبار `pytest`** (`tests/test_all.py` + `tests/test_community_and_protocols.py` + `tests/test_enterprise_platform.py` + `tests/test_security_ranking_and_api.py` + `tests/test_historical_intelligence.py` + `tests/test_top500_architecture.py`).
  - **`34/34` اختبار `JUnit / Robolectric`** (`:app` + `:admin` شاملةً `AndroidVpnAuditTest`، `CommunityAndHotspotTest` للتحقق من هوتسبوت الـ VPN بدون روت والفحص المجتمعي الموثّق لإيران وبروتوكولَي `SOCKS5`/`HTTP`، `EnterpriseAndroidTest`، `LeakKillSwitchAndSecurityTest`، `SmartVpnUpgradeTest`، `Top500AndPersonalizedTop50Test`، و`AdminAppUnitTest`).

---

## 7) التوثيق الهندسي المرجعي الكامل والشفافية الأمنية (`v1`)

- **معمارية أندرويد (`v1` — Bilingual AR/EN + Central Top 500 + Local Personalized Top 50 + Play Protect Hardening):** [`docs/ANDROID_ARCHITECTURE.md`](docs/ANDROID_ARCHITECTURE.md) | [`docs/ANDROID_BATTERY_OPTIMIZATION.md`](docs/ANDROID_BATTERY_OPTIMIZATION.md) | [`android/README.md`](android/README.md)
- **مخططات قواعد البيانات ونموذج الأمان والخصوصية:** [`docs/DATABASE_SCHEMA.md`](docs/DATABASE_SCHEMA.md) | [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) | [`SECURITY.md`](SECURITY.md) | [`PRIVACY.md`](PRIVACY.md)
- **البنية المعمارية الشاملة والنشر السحابي وسجل الإصدارات:** [`ARCHITECTURE.md`](ARCHITECTURE.md) | [`DEPLOYMENT.md`](DEPLOYMENT.md) | [`docs/ENTERPRISE_ARCHITECTURE_AND_OPERATIONS.md`](docs/ENTERPRISE_ARCHITECTURE_AND_OPERATIONS.md) | [`CHANGELOG.md`](CHANGELOG.md)
- **توثيق واجهة الإحصاءات العامة (`API v1`) وتقارير الاختبار:** [`API.md`](API.md) | [`TESTING.md`](TESTING.md) | [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md)
- **التزام الخصوصية والشفافية الصارمة:** لا يسجّل التطبيق ولا المنصة أي سجل تصفح أو عناوين `SSID` أو كلمات مرور، ولا يرفع سجل الفحص الشخصي لأي خادم خارجي، ويعامل السيرفرات العامة دائمًا كغير موثوقة المشغّل (`UNKNOWN_SERVER_TRUST`) دون مساواة السرعة بالأمان أو الخصوصية.
