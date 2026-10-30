# ULTIMATE VPN ENTERPRISE v3.1 — التوثيق الهندسي، الأمني، والتشغيلي الشامل (100% على GitHub)

## 1. المعمارية السحابية الخالية من الخوادم الخارجية (100% Pure-GitHub Architecture)

تعمل المنصة بالكامل داخل منظومة **GitHub** دون أي خادم خارجي (Zero VPS / Zero Third-Party Cloud):

| المكوّن | المسار البرمجي | آلية التشغيل على GitHub |
|---|---|---|
| **تطبيق المشترك (User APK `v3.1`)** | `android/app/` (`com.bahrain.vpnconfigs`) | مقلّص الحجم عبر `R8 + Resource Shrinking`، يفك تشفير عقد `VIP` الخاصة للمشتركين الفعّالين فقط، يضم محرك التبديل التلقائي السريع (`~2s Auto-Failover`) ومحدّث `Split ABI` الذكي، ويُنشر موقّعًا على **GitHub Releases**. |
| **تطبيق المشرف المستقل (Admin APK `v3.1`)** | `android/admin/` (`com.bahrain.vpnadmin`) | تطبيق مستقل رشيق (`app-admin-release.apk`) يتحقق من رمز `TOTP 2FA`، يدير ويشفّر عقد `VIP` الخاصة (`AES-256-GCM`)، ويوقّع التراخيص (`ECDSA P-256`) عبر `api.github.com`. |
| **لوحة التحكم الويب المعيارية (17 صفحة AR/EN)** | `web-admin/` + `web-admin/modules/` | مبنية بهيكلية معيارية (`Modular JS`) على **GitHub Pages** (`gh-pages`) بتشفير **WebCrypto** ثنائية اللغة (عربي RTL / إنجليزي LTR) مع إدارة عقد `VIP` المشفّرة وتصدير CSV/Excel وPDF. |
| **محرك البيانات والأمان والذكاء الاصطناعي** | `enterprise/` (`database.py`, `crypto_security.py`, `ai_intelligence.py`, `publisher.py`) | يعمل عبر **GitHub Actions** (`enterprise.yml` + `data.yml`) على قاعدة SQLite علائقية مكونة من **22 جدولًا مطبّعًا** (`001..003`) مع نسخ احتياطي مشفّر (`AES-256-GCM`). |

---

## 2. مخطط قاعدة البيانات العلائقية المطبّعة (21 جدولًا) والترحيلات (Migrations)

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

1. **تفعيل لوحة الويب (GitHub Pages):**
   - ينشر سير عمل `.github/workflows/enterprise.yml` محتويات `web-admin/` تلقائيًا إلى فرع `gh-pages`.
   - من إعدادات المستودع على GitHub (`Settings -> Pages`)، اختر الفرع `gh-pages` والمجلد `/ (root)` لتعمل اللوحة مباشرة على `https://oldman-552.github.io/vpn-configs/`.
2. **تطبيقات الأندرويد الموقّعة (GitHub Releases `v3.1`):**
   - يبني `.github/workflows/apk.yml` كلاً من تطبيق المشترك (`app-arm64-v8a-release.apk`, `app-release.apk`, `app-x86_64-release.apk`) وتطبيق المشرف المستقل (`app-admin-release.apk`) مع ضغط `R8 + Resource Shrinking` ويرفق ملف البصمات `SHA256SUMS.txt` في إصدارات GitHub الرسمية (`v3.1` و`latest-apk`).

---

## 6. ترقيات الإصدار `v3.1` الهندسية

1. **تقليص الحجم (`R8 + Resource Shrinking`) والتحديث الذكي حسب معمارية المعالج (`Split per ABI`):** إزالة آلاف كلاسات الأيقونات غير المستخدمة، وتوجيه `AppUpdateManager` لتحميل حزمة `arm64-v8a` الرشيقة تلقائيًا على هواتف `ARM64` مع التحقق من بصمة `SHA-256`.
2. **سيرفرات `VIP` الخاصة المشفّرة للمشتركين فقط (`Encrypted VIP Private Nodes`):** تُشفّر بـ `AES-256-GCM` (`AAD = bahrain-vpn-vip-nodes-v31`) داخل `bundle.json`، ولا يُكشف مفتاح فك تشفيرها إلا داخل مغلف شهادة المشترك النشط (`envelope_b64`)، مع منع نسخ الرابط الخام أو تصديره في الملفات النصية.
3. **محرك التبديل التلقائي الذكي السريع (`SmartFailoverEngine ~2s`):** فحص تأكيدي مزدوج خلال `600ms` عند أول تعثر لنقل النفق فورًا إلى أسرع سيرفر شغّال (بأولوية `VIP` ثم أعلى سرعة مقاسة على الهاتف) دون هدم واجهة `TUN` ومع عزل السيرفر المتذبذب لمدة دقيقتين (`Cooldown`).
4. **التفكيك المعياري للكود (`Modularization`):** تقسيم واجهات `EnterpriseScreens.kt` إلى حزمة `ui/enterprise/` وتقسيم `web-admin/app.js` إلى وحدات مستقلة في `web-admin/modules/`.

