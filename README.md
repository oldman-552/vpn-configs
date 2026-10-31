# bahrain-vpn v2 (@data) — مخرجات البيانات السحابية الرسمية المولّدة آليًا

هذا الفرع (`data`) يتبع الإصدار الرسمي الموحّد **`bahrain-vpn v2`** ويُعاد بناؤه والتحقق التشفيري منه آليًا كل 30 دقيقة عبر `.github/workflows/data.yml` — لا تعدّله يدويًا.

- **الإصدار الرسمي لتطبيق الأندرويد والمشرف (`bahrain-vpn v2` — العربية أساسية + الإنجليزية):** https://github.com/oldman-552/vpn-configs/releases/tag/v2

| الملف | الوصف الهندسي (`v2`) | الرابط المباشر (`jsDelivr CDN`) |
|---|---|---|
| `top500.manifest.json` | بيان الإصدار وبصمات SHA-256 وحالة التحديث التفاضلي لحزمة المرشّحات المركزية | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/top500.manifest.json |
| `top500.json` | حزمة المرشّحات المركزية المؤهّلة (حتى 500 سيرفر بدون حشو — اختيار Top 50 محلي على أندرويد فقط) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/top500.json |
| `top500.delta.json` | التحديث التفاضلي الموقّع بـ SHA-256 بين آخر إصدارين لحزمة Top 500 | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/top500.delta.json |
| `top500.txt` | الروابط الخام المطبّعة لحزمة المرشّحات المركزية Top 500 | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/top500.txt |
| `iran-top500.json` | قائمة السيرفرات الموثّقة مجتمعيًا من داخل شبكات إيران المباشرة (`IR` — تقييم متعدد الأجهزة بدون حشو) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/iran-top500.json |
| `iran-top500.txt` | الروابط الخام المطبّعة لقائمة سيرفرات إيران الموثّقة مجتمعيًا (`IR`) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/iran-top500.txt |
| `iran-results.json` | السجل التحليلي الكامل لقياسات الفحص المجتمعي الموثّق من داخل إيران (`IR`) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/iran-results.json |
| `sub.txt` | اشتراك Base64 الشامل لجميع العُقد الحيّة بوسم `bahrain-vpn` | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/sub.txt |
| `best100.txt` | أفضل 100 عقدة متنوّعة المضيفين والشبكات الفرعية (/24) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/best100.txt |
| `privacy_aware.txt` | الأعلى أمانًا في طبقة النقل (Verified TLS/Reality فقط بدون allowInsecure) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/privacy_aware.txt |
| `reliable.txt` / `reliable_sub.txt` | الأعلى استقرارًا واعتمادية عبر الجولات المتتالية (نصي + Base64) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/reliable_sub.txt |
| `low_latency.txt` | الأقلّ زمن استجابة وتذبذبًا (Median RTT + Jitter) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/low_latency.txt |
| `high_throughput.txt` | الأعلى سرعة تنزيل موثّقة عبر النفق الفعلي | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/high_throughput.txt |
| `alive.json` / `alive.txt` | البيانات الكاملة والروابط الحيّة مع الدولة والدرجة والتقييم الأمني | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/alive.json |
| `servers-current.json` | الحالة الحالية لجميع السيرفرات بهويات `server_id` معماة خالية من بيانات الاعتماد | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/servers-current.json |
| `servers-history.json` | السجل التاريخي للجاهزية (24h/7d/30d/90d) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/servers-history.json |
| `servers-performance.json` | تحليلات الأداء النافذية (avg/median/p95 للتأخير والتذبذب والسرعة) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/servers-performance.json |
| `servers-statistics.json` | الإحصاءات الشاملة والجاهزية وفئات الأعطال الـ 10 | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/servers-statistics.json |
| `api/v1/statistics.json` | واجهة الإحصاءات العامة القرائية المعماة (`OpenAPI 3.1.0`) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/api/v1/statistics.json |
| `enterprise/bundle.json` | حزمة التراخيص الموقّعة (`ECDSA P-256` — `v2` / `2.0`) وعُقد VIP المشفّرة | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/enterprise/bundle.json |
| `countries.json` | فهرس الدول المُحقّقة عبر النفق الفعلي | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/countries.json |
| `source_health.json` | تقرير صحّة وتفرّد المصادر وعزلها (بدون أسرار) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/source_health.json |
| `all.txt.gz` | المجمع البنيوي النظيف الكامل مضغوطًا | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/all.txt.gz |
| `meta.json` | ملخص الدورة الشامل ومؤشرات الصحّة والأمان (`v2`) | https://cdn.jsdelivr.net/gh/oldman-552/vpn-configs@data/meta.json |
