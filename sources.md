# سجل وحوكمة المصادر المنتقاة (Source Governance & Empirical Audit)

> آخر تدقيق كمّي مباشر عبر `api.github.com` وبمقارنة البصمات المعيارية (`Layer-2 SHA-256`) مع فرع `data` الحيّ: **2026-10-29**.
> جميع المصادر النشطة مضمّنة في [`github_sources.txt`](github_sources.txt) (`26` تغذية HTTPS منتقاة) إلى جانب `277` قناة تلغرام فريدة في [`channels.txt`](channels.txt).

---

## 1) منهجية القبول والتقييم الكمّي

لا يُضاف أي مصدر إلى `github_sources.txt` بمجرّد عدد الأسطر الخام؛ بل يُقاس كل مرشّح عبر `dedupe.py` و `source_stats.py` وفق خمسة معايير صارمة:
1. **الحداثة والاستمرارية (Freshness):** نشاط تحديث فعلي وحديث (استبعاد المستودعات المهجورة أو المؤرشفة أو مجرّد الـ Forks الراكدة).
2. **السلامة البنيوية والأمنية (Safety):** روابط HTTPS مباشرة فقط، ضمن سقف الحجم (`MAX_FEED_BYTES`)، مع رفض أي عنوان يشير إلى شبكات داخلية أو `localhost`.
3. **الإضافة الحصرية الحقيقية (Marginal Exclusive Yield):** عدد الهويات البروتوكولية الفريدة (`Layer-2 Identity`) والمضيفين (`host:port`) التي يضيفها المصدر **ولا توجد في المصادر الأخرى**.
4. **انخفاض التداخل (Low Overlap):** تقاعد أو استبعاد المرايا التي تتطابق بنسبة `>85–100%` مع مصادر أساسية أخفّ حجمًا وأسرع تحديثًا.
5. **نسبة العُقد الحيّة الموثّقة (Live Hit Rate):** تقاطع المصدر مع العُقد التي اجتازت فحص النفق الحقيقي (`Xray` / `sing-box`).

---

## 2) المصادر النشطة المعتمدة في `github_sources.txt` (26 تغذية عبر 3 فئات)

### الفئة الأولى (Tier 1): مصادر مفحوصة مسبقًا بالاتصال الفعلي (أولوية قصوى في أخذ العيّنات)
| المعرّف | المستودع / المسار | الترخيص | صالح | إضافة حصرية / ملاحظات القياس |
|---|---|---|---:|---|
| `mahdibland-443` | `mahdibland/V2RayAggregator@master:Eternity` | GPL-3.0 | 184 | نواة استقرار مفحوصة دوريًا (`33` مطابقة حيّة) |
| `epodonios` | `Epodonios/v2ray-configs@main:All_Configs_Sub.txt` | GPL-3.0 | 871 | `395` هوية حصرية (`45.4%`) و `53` مطابقة حيّة |
| `sevcator` | `sevcator/5ubscrpt10n@main:protocols/{vl,vm,tr,ss}.txt` (4 تغذيات) | Unlicense | 2,068 | مصنّف حسب البروتوكول ومفحوص عبر `xray-knife` |
| `matin-super` | `MatinGhanbari/v2ray-configs@subs:merged/super-sub.txt` | GPL-3.0 | 200 | باقة النخبة المفحوصة (`36.0%` حصرية، `40` مطابقة حيّة) |
| `ermaozi-tested` | `ermaozi/get_subscribe@main:subscribe/reachable/v2ray.txt` | Apache-2.0 | 388 | عُقد اجتازت فحص الوصول المسبق (`43` مطابقة حيّة) |
| `4n0nymou3-tested` | `4n0nymou3/multi-proxy-config-fetcher@main:configs/proxy_configs_tested.txt` | MIT | 278 | النسخة المفحوصة مباشرة من المولّد الأصلي (`46` مطابقة حيّة) |

### الفئة الثانية (Tier 2): مستودعات متنوّعة عالية القيمة الحصرية ومنخفضة التداخل
| المعرّف | المستودع / المسار | الترخيص | صالح | التداخل | الإضافة الحصرية للنظام |
|---|---|---|---:|---:|---|
| `subcrawler-vless` | `Leon406/SubCrawler@main:sub/share/vless` | Apache-2.0 | 18,233 | `2.6%` | **`+14,055` هوية جديدة** و `70` مطابقة حيّة |
| `subcrawler-vmess` | `Leon406/SubCrawler@main:sub/share/v2` | Apache-2.0 | 339 | `4.1%` | `95.9%` حصرية لتعزيز بروتوكول VMess |
| `subcrawler-ss` | `Leon406/SubCrawler@main:sub/share/ss` | Apache-2.0 | 239 | `0.4%` | `99.6%` حصرية لبروتوكول Shadowsocks |
| `subcrawler-tr` | `Leon406/SubCrawler@main:sub/share/tr` | Apache-2.0 | 54 | `2.3%` | `97.7%` حصرية لبروتوكول Trojan |
| `subcrawler-hy2` | `Leon406/SubCrawler@main:sub/share/hysteria2` | Apache-2.0 | 6 | `16.7%` | تغذية مخصّصة لبروتوكول Hysteria2 |
| `subcrawler-tuic` | `Leon406/SubCrawler@main:sub/share/a11` | Apache-2.0 | 103 | `11.6%` | دعم إضافي لعُقد TUIC/Hysteria2 الحديثة |
| `0xradikal-all` | `0xRadikal/Free-v2ray-Configs@main:all/configs.txt` | MIT | 10,804 | `41.1%` | **`+2,555` هوية جديدة** و `72` مطابقة حيّة |
| `barabama-merged` | `Barabama/FreeNodes@main:nodes/merged.txt` | MIT | 3,575 | `6.8%` | **`+2,521` هوية جديدة** (`93.2%` غير متداخلة) |
| `delta-kronecker` | `Delta-Kronecker/V2ray-Config@main:config/all_configs.txt` | Unspecified | 2,873 | `13.7%` | **`+1,939` هوية جديدة** و `65` مطابقة حيّة |
| `ebrasha` | `ebrasha/free-v2ray-public-list@main:all_extracted_configs.txt` | GPL-3.0 | 3,157 | `52.1%` | `+1,431` هوية حصرية و `71` مطابقة حيّة |
| `solispirit` | `SoliSpirit/v2ray-configs@main:all_configs.txt` | MIT | 4,060 | `76.5%` | `+919` هوية حصرية و `71` مطابقة حيّة |
| `roosterkid` | `roosterkid/openproxylist@main:V2RAY_RAW.txt` | Unlicense | 500 | `11.2%` | `88.8%` حصرية (تم إصلاح فرع `master` القديم إلى `main`) |

### الفئة الثالثة (Tier 3): روافد تكميلية خفيفة وموجّهة لتنوّع البروتوكولات والمناطق
| المعرّف | المستودع / المسار | الترخيص | صالح | سبب الاعتماد |
|---|---|---|---:|---|
| `mheidari98-ss` / `mheidari98-trojan` | `mheidari98/.proxy@main:{ss,trojan}` | Unspecified | 6,639 | أُخذ الملفان البروتوكوليان الخفيفان (`1.2 MB`) بدل ملف `all` المتضخّم (`12.2 MB`) |
| `v2rayroot-vless` / `v2rayroot-ss` | `V2RayRoot/V2RayConfig@main:Config/{vless,shadowsocks}.txt` | Unspecified | 501 | تداخل شبه صفري (`2.4%–3.4%`) وإضافة صافية |
| `yebekhe-psg` | `itsyebekhe/PSG@main:config.txt` | MIT | 313 | خلفٌ نشط وحديث لمستودعات Yebekhe القديمة (`+211` هوية جديدة) |
| `mahdi0024-sub` | `Mahdi0024/ProxyCollector@master:sub/proxies.txt` | Unspecified | 455 | `+169` هوية جديدة و `50` مطابقة حيّة |
| `igareck-vless` / `igareck-ss` | `igareck/vpn-configs-for-russia@main:BLACK_{VLESS,SS+All}_RUS.txt` | GPL-3.0 | 161 | `97%–99%` عُقد حصرية تمامًا في شبكات أوروبية غير مغطّاة بالمجمّعات الفارسية |
| `free18-v2ray` | `free18/v2ray@main:v.txt` | Unspecified | 82 | خفيف جدًا (`2.5%` تداخل فقط) ومحدّث باستمرار |

---

## 3) المصادر المتقاعدة أو المرفوضة بعد الفحص التجريبي (مع السبب الهندسي الدقيق)

| المستودع المرشّح / السابق | القرار | السبب الكمّي الموثّق |
|---|---|---|
| `ALIILAPRO/v2rayNG-Config` | **تقاعد (`retired`)** | `0%` إضافة حصرية بعد إدراج `0xRadikal` و `SoliSpirit` (نسخة مكررة بالكامل) |
| `Rayan-Config/C-Sub` | **تقاعد (`retired`)** | `0%` إضافة حصرية (`100%` مشمول مسبقًا في المصادر النشطة) |
| `barry-far/V2ray-config` | **تقاعد (`retired`)** | `95.9%` تداخل مكرر بحجم خام كبير (`~2 MB`) يبطئ الجمع بلا عائد يُذكر |
| `yebekhe/TelegramV2rayCollector` (`saeed-mirror`) | **استُبدل** | كان يشير في الواقع إلى مستودع آخر مع تسمية مضلّلة؛ استُبدل بالمصدرين الأصليين `4n0nymou3-tested` و `itsyebekhe/PSG` |
| `coldwater-10/V2ray-Config` | **مرفوض (`stale`)** | مهجور منذ `2025-01-04` ولا يتلقّى تحديثات حيّة |
| `morpheusadam/v2ray-config` | **مرفوض (`incompatible`)** | يحتوي بروكسيات `HTTP/SOCKS` نصية فقط (`0` روابط V2Ray/VLESS/Trojan/HY2) |
| `chengaopan/AutoMergePublicNodes` | **مرفوض (`duplicate`)** | `100.0%` نسخة مطابقة من `ermaozi/get_subscribe` |
| `peasoft/NoMoreWalls` | **مرفوض (`duplicate`)** | `99.5%` نسخة مكررة من `ermaozi/get_subscribe` |
| `Surfboardv2ray/TGParse` | **مرفوض (`duplicate`)** | `100.0%` تداخل مع قنوات التلغرام والمجمّعات النشطة |
| `MhdiTaheri/V2rayCollector` | **مرفوض (`duplicate`)** | `100.0%` تداخل بدون أي هوية حصرية جديدة |
| `Firmfox/Proxify` | **مرفوض (`high_overlap`)** | `89.6%` تداخل مع تضخّم حجمي كبير (`>4 MB`) |
| `Pawdroid/Free-servers` | **مرفوض (`low_yield`)** | `5` عُقد فقط و `0` عناوين مضيفين جديدة |

---

## 4) دورة حياة المصادر المؤتمتة (Source Lifecycle State Machine)

يتتبّع النظام (`scoring.py` ← `SourceHealthRegistry`) كل مصدر عبر الدورات المتعاقبة في `state/source_state.json` وينشر التقرير العلني الآمن في `source_health.json`:

- **`active`**: يعمل بنجاح وينتج كانفيغات صالحة.
- **`temporarily_failed`**: تعثّر عابر في الجلب (`1–2` دورة)؛ يستمر النظام بمحاولة جلبه.
- **`degraded`**: فشل متكرر (`>=3` دورات) أو استجابة `HTTP 200` خالية من الكانفيغات الصالحة.
- **`disabled`**: تجاوز عتبة الفشل المستمر (`>=5` دورات)؛ يدخل تلقائيًا في **فترة تهدئة (Cooldown)** بحيث لا يُفحص إلا كل رابع دورة لتوفير وقت الخادم، ويعود إلى `active` تلقائيًا فور تعافيه.
- **`retired`**: مصدر أُحيل للتقاعد بسبب التداخل الكامل أو الإهمال الدائم.
- **`pending_validation`**: مصدر مرشّح اكتُشف عبر `python source_stats.py --discover` وحقّق قيمة حصرية مبدئية، وينتظر المراجعة قبل ترقيته إلى `github_sources.txt`.
