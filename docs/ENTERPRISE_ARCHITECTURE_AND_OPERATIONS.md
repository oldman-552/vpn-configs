# ULTIMATE VPN ENTERPRISE v2 — التوثيق الهندسي، الأمني، والتشغيلي الشامل (100% على GitHub)

## 1. المعمارية السحابية الخالية من الخوادم الخارجية (100% Pure-GitHub Architecture)

تعمل المنصة بالكامل داخل منظومة **GitHub** دون أي خادم خارجي (Zero VPS / Zero Third-Party Cloud):

| المكوّن | المسار البرمجي | آلية التشغيل على GitHub |
|---|---|---|
| **تطبيق المشترك (User APK `v2`)** | `android/app/` (`com.bahrain.vpnconfigs` — `versionCode = 2`, `versionName = "2.0"`) | ثنائي اللغة (**العربية أساسية `RTL` + الإنجليزية `LTR`**)، مقلّص الحجم عبر `R8`، يضم مشاركة VPN عبر الهوتسبوت بدون روت (`Rootless VPN Hotspot`)، الفحص المجتمعي الطوعي الموثّق لإيران (`IR`)، استثناء `.ir` تلقائياً، منع تسرب `DNS/IPv6`، مفتاح إيقاف حقيقي (`Fail-Closed Kill Switch`)، فك تشفير عقد `VIP 💎`، ومحدّث `Split ABI` الموثّق على **GitHub Releases (`v2`)**. |
| **تطبيق المشرف المستقل (Admin APK `v2`)** | `android/admin/` (`com.bahrain.vpnadmin` — `versionCode = 2`, `versionName = "2.0"`) | تطبيق مستقل رشيق ثنائي اللغة (`AR/EN`) يتحقق من رمز `TOTP 2FA`، يدير ويشفّر عقد `VIP` الخاصة (`AES-256-GCM`)، ويوقّع التراخيص (`ECDSA P-256`) عبر `api.github.com`. |
| **لوحة الإدارة (17 صفحة) + المراقبة الحيّة** | `web-admin/` + `web-admin/modules/` + `monitor.{html,js}` | مستضافة على **GitHub Pages** (`gh-pages`): لوحة مشرف مشفّرة بـ **WebCrypto** (`index.html`) + شاشة مراقبة حيّة عامة قرائية (`monitor.html`) ثنائية اللغة (AR/EN) مع رسوم اتجاهات `SVG`. |
| **محرك الذكاء الأمني والبيانات وواجهة `API v1`** | `enterprise/` + `security_intelligence.py` + `public_api.py` | يعمل عبر **GitHub Actions** (`enterprise.yml` + `data.yml`) على قاعدة SQLite من **24 جدولًا مطبّعًا** (`001..003`)، مع حجر صحي للعُقد المشبوهة وتصدير واجهة `/api/v1/*` المعماة. |

---

## 2. مخطط قاعدة البيانات العلائقية المطبّعة (24 جدولًا) والترحيلات (Migrations)

تقع ملفات الترحيل في `enterprise/migrations/`:
- `001_initial_enterprise_schema.sql`: ينشئ الجداول الـ 21 مع `PRAGMA foreign_keys = ON` والفهارس وقيود `CHECK`:
  1. `users` — حسابات المشتركين، تجزئة `Argon2id`، وحالة الحساب (`ACTIVE`, `FREE_TRIAL`, `EXPIRED`, `SUSPENDED`, `BLOCKED`, `DISABLED`).
  2. `user_subscriptions` — سجل الباقات الـ 8 (`FREE_TRIAL`, `DAILY`, `WEEKLY`, `MONTHLY`, `THREE_MONTHS`, `SIX_MONTHS`, `YEARLY`, `LIFETIME`).
  3. `trial_activations` — سجل التجربة المجانية 48 ساعة (`UNIQUE(user_id)` لمنع تكرار التجربة أو إعادة التثبيت).
  4. `bandwidth_limits` — سقوف سرعة التنزيل والرفع والحصة اليومية والشهرية وخيار الحظر التلقائي.
  5. `data_usage` — الاستهلاك اليومي والشهري لكل مشترك.
  6. `user_devices` — الأجهزة الموثّقة بمعرّف التثبيت العشوائي (`inst_...`) وفق قاعدة `1 حساب = 1 جهاز`.
  7. `device_violations` — محاولات تسجيل الدخول من أجهزة إضافية غير مصرّحة وحالة الحظر التلقائي.
  8. `login_attempts` — سجل محاولات الدخول والحماية من التخمين (Rate Limiting / Lockout).
  9. `user_sessions` — جلسات اتصال الـ VPN، البروتوكول، نبضات الحياة، وقطع الجلسة عن بعد.
  10. `servers` — الخوادم الحيّة ومؤشرات التصنيف الذكي (`EXCELLENT`, `VERY_GOOD`, `GOOD`, `AVERAGE`, `POOR`, `OFFLINE`).
  11. `server_health` — السجل الزمني لفحوصات الاستجابة والتذبذب والاستقرار.
  12. `speed_tests` — قياسات سرعة العميل الفعلية (`Download`, `Upload`, `Ping`, `Jitter`, `Packet Loss`).
  13. `network_tests` — فحوصات تسرب `DNS` و`IP` وصلاحية شهادات `TLS` واستقرار النفق.
  14. `connection_logs` — سجلات أحداث الاتصال المصنّفة بدون أي تتبع لتصفح المستخدم.
  15. `app_versions` — إصدارات `USER` و`ADMIN` وبصمات `SHA-256` للتحديث الرسمي الموقّع.
  16. `app_crashes` — تقارير الانهيارات (`CRASH`, `ANR`) وزمن الإقلاع واستهلاك الذاكرة.
  17. `notifications` — مركز التنبيهات الأمنية والتشغيلية ثنائي اللغة.
  18. `remote_config` — الإعدادات البعيدة الفورية المحمية بالتأكيد للإعدادات الحساسة.
  19. `admin_roles` — أدوار الصلاحيات (`SUPER_ADMIN`, `OPERATOR`, `AUDITOR`).
  20. `admin_users` — حسابات المشرفين مع تجزئة `Argon2id` ومفاتيح `TOTP 2FA` وقفل المحاولات الفاشلة.
  21. `admin_audit_logs` — سجل التدقيق الأمني المتسلسل ببصمات `SHA-256` المقاومة للعبث (`prev_hash -> entry_hash`).
- `002_seed_roles_and_defaults.sql`: يزرع الأدوار الافتراضية والإعدادات الآمنة المبدئية.
- `003_v31_vip_and_abi_updates.sql`: يضيف الجداول الـ 3 المكملة للـ 24 جدولًا (`vip_servers`, `vip_access_keys`, `vip_audit_events`) ودعم حزم `abi_assets_json` في جدول `app_versions`.

---

## 3. البروتوكول التشفيري والأمني (Zero-Secret Client Security)

1. **صفر أسرار في تطبيق المستخدم (`User APK`):** لا يحتوي تطبيق المشترك على أي `GitHub Token` أو مفتاح خاص أو بيانات مشرف، ويتم التحقق من ذلك آليًا في `.github/workflows/apk.yml` عبر فحص `aapt2` وملفات `.dex` و`.class`.
2. **مغلفات الترخيص صفرية المعرفة (Zero-Knowledge License Envelopes):**
   - معرّف البحث المعمّى: `HMAC-SHA256("bahrain-vpn-enterprise-v3-user-lookup", username)`.
   - اشتقاق مفتاح فك الشهادة على هاتف المشترك: `PBKDF2-HMAC-SHA256(120,000 iterations)` + `AES-256-GCM` مع `AAD = username`.
   - التحقق الرقمي من عدم التزوير: توقيع `ECDSA P-256 (SHA-256)` على النص القانوني الموحّد (`Canonical JSON`) متوافق بين Python وAndroid JCA ومتصفح WebCrypto.
3. **مقاومة التلاعب بالوقت (Anti-Clock-Tamper 48h Trial):** يربط `EnterpriseClock` طابع وقت الشبكة الموثوق (`HTTP Date` + `generated_at` الموقّع) بساعة النواة الرتيبة (`SystemClock.elapsedRealtime()`) لمنع تمديد التجربة بتغيير ساعة الهاتف.

---

## 4. النسخ الاحتياطي المشفّر والاستعادة الموثّقة (Backup & Disaster Recovery)

- **التوليد الآلي:** ينفّذ `create_encrypted_sqlite_backup()` لقطة متسقة عبر واجهة `sqlite3.Connection.backup()`، يضغطها بـ `gzip`، يحسب بصمة `SHA-256` للنص الأصلي، ثم يشفّرها بـ `AES-256-GCM` (`PBKDF2 120k`) مع الاحتفاظ بآخر 14 نسخة مشفّرة.
- **الاستعادة والفحص:** يتحقق `restore_encrypted_sqlite_backup()` من صحة التشفير، يطابق بصمة `SHA-256`، ثم يشغّل `PRAGMA integrity_check;` على قاعدة البيانات المستعادة قبل اعتمادها.
- **التشغيل اليدوي عبر سطر الأوامر أو GitHub Actions:**
  ```bash
  ENTERPRISE_MASTER_KEY="your-strong-passphrase" python -m enterprise.publisher \
    --vault enterprise/vault/enterprise_vault.enc.json \
    --alive dist/alive.json \
    --bundle-out dist/enterprise/bundle.json \
    --backup-dir dist/enterprise/backups
  ```

---

## 5. دليل النشر والتشغيل السريع على GitHub

1. **تفعيل لوحتَي الإدارة والمراقبة (GitHub Pages):**
   - ينشر سير عمل `.github/workflows/enterprise.yml` محتويات `web-admin/` تلقائيًا إلى فرع `gh-pages`.
   - من إعدادات المستودع على GitHub (`Settings -> Pages`)، اختر الفرع `gh-pages` والمجلد `/ (root)` لتعمل لوحة الإدارة المشفّرة على `https://oldman-552.github.io/vpn-configs/` وشاشة المراقبة العامة على `https://oldman-552.github.io/vpn-configs/monitor.html`.
2. **تطبيقات الأندرويد الموقّعة (GitHub Releases `v2`):**
   - يبني `.github/workflows/apk.yml` كلاً من تطبيق المشترك (`app-arm64-v8a-release.apk`, `app-release.apk`, `app-x86_64-release.apk`) وتطبيق المشرف المستقل (`app-admin-release.apk`) باللغتين العربية (أساسية) والإنجليزية مع ضغط `R8 + Resource Shrinking` وتوقيع `RSA-4096 v1/v2/v3` ويرفق ملف البصمات `SHA256SUMS.txt` في الإصدار الرسمي الوحيد **`v2`** (`Latest`).

---

## 6. المميزات الهندسية الأساسية في الإصدار الرسمي `v2`

1. **واجهة ثنائية اللغة (العربية أساسية `RTL` + الإنجليزية `LTR`) وتقليص الحجم (`R8 + Split per ABI`):** دعم كامل للغتين مع بقاء العربية اللغة الافتراضية الأساسية، وتوجيه `AppUpdateManager` لتحميل حزمة `arm64-v8a` الرشيقة تلقائيًا عبر متصفح النظام الرسمي مع التحقق من بصمة `SHA-256`.
2. **سيرفرات `VIP` الخاصة المشفّرة للمشتركين فقط (`Encrypted VIP Private Nodes`):** تُشفّر بـ `AES-256-GCM` داخل `bundle.json`، ولا يُكشف مفتاح فك تشفيرها إلا داخل مغلف شهادة المشترك النشط (`envelope_b64`)، مع منع نسخ الرابط الخام أو تصديره في الملفات النصية.
3. **منع تسرب `DNS/IPv6` ومفتاح الإيقاف الصارم (`Zero-Leak & Fail-Closed Kill Switch`):** توجيه `tunnel-dns` إجباريًا داخل النفق (`detour="proxy"`)، التقاط المسار `::/0` دائمًا لمنع تسرب IPv6 على الشبكات المزدوجة، قفل `tun0` قبل فحص السيرفر، والاحتفاظ بالحجب الفعّال (`PROTECTION_ACTIVE`) عند انقطاع جميع البدائل.
4. **محرك التبديل التلقائي الاستباقي وذكاء الأمان وواجهة `API v1`:** دعم سياسات `OFF / SMART / AGGRESSIVE` مع `Hysteresis 25s` وفحص البدائل على المنافذ `20901..20904` دون قطع النفق، فصل تقييم الأمان والخصوصية عن السرعة (`security_intelligence.py` + `SecurityEvaluator.kt`)، ونشر واجهة الإحصاءات العامة المعماة `/api/v1/*` مع مواصفة `OpenAPI 3.1.0`.

