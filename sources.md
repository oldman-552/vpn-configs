# مصادر كانفيغات مجانية على GitHub — مرجع سريع

> كل الأرقام (النجوم، آخر تحديث، عدد الكانفيغات) تم فحصها مباشرة من GitHub API ومن ملفات الاشتراك بتاريخ **2026-10-29**.
> عدد الكانفيغات = الأسطر الفعلية في ملف الاشتراك، و`unique_ep` = عدد المضيف:المنفذ الفريدة.

## 1) مستودعات اشتراكات (تُحدَّث تلقائيًا عبر GitHub Actions)

| المستودع | ★ | آخر دفعة | ملف الاشتراك | كانفيغ | nodes فريدة | مزيج البروتوكولات |
|---|---|---|---|---|---|---|
| `SoliSpirit/v2ray-configs` | 635 | 2026-10-29 | `https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt` | 11,013 | 6,028 | vless 5040 / vmess 3916 / ss 1400 / trojan 657 |
| `MatinGhanbari/v2ray-configs` | 691 | 2026-10-29 | `.../subscriptions/v2ray/all_sub.txt` (+ `super-sub.txt` = أفضل 200 بعد اختبار) | 4,001 | 3,297 | vmess 2613 / ss 878 / vless 247 / trojan 235 |
| `ALIILAPRO/v2rayNG-Config` | 372 | 2026-10-29 | `.../ALIILAPRO/v2rayNG-Config/main/sub.txt` | 3,984 | 2,412 | vmess 3404 / vless 578 |
| `ermaozi/get_subscribe` | 9,403 | 2026-10-29 | `.../get_subscribe/main/subscribe/v2ray.txt` | 560 | 464 | vless 301 / ss 61 / trojan 45 / hysteria2 38 |
| `barry-far/V2ray-Config` | 2,605 | 2026-10-29 | `.../V2ray-config/main/Sub1.txt` … `Sub8.txt` | 499 (Sub1) | 217 | ss 452 / hysteria2 33 |
| `mahdibland/V2RayAggregator` | 4,024 | 2026-10-29 | `.../V2RayAggregator/master/Eternity` | 200 | 195 | ss 125 / vmess 57 / trojan 17 |
| `roosterkid/openproxylist` | 941 | 2026-10-29 | `.../openproxylist/main/V2RAY_RAW.txt` | 150 | 144 | vless 66 / ss 32 / trojan 30 |
| `Leon406/SubCrawler` | 1,573 | 2026-10-29 | `.../SubCrawler/master/sub/share/{vless,hysteria2}` و `main/sub/share/a11` | — | — | مُختبَر سرعة داخليًا |
| `Pawdroid/Free-servers` | 19,683 | 2026-10-29 | `.../Pawdroid/Free-servers/main/sub` | 9 | 9 | صغير جدًا، لكن المستودع نشط |
| `Au1rxx/free-vpn-subscriptions` | — | 2026-10-19 | `.../free-vpn-subscriptions/raw/main/output/v2ray-base64.txt` | ~150 منشور | — | يمرّر HTTP حقيقي قبل النشر (204) |

**تحذير:** `freefq/free` (★43k — الأشهر تاريخيًا) **متوقّف عن التحديث منذ 2024-08**؛ روابطه ميتة عمليًا رغم أنه أول نتيجة في كل بحث. لا تعتمد عليه.

### ملفات مقسّمة حسب البروتوكول (مفيدة إن أردت Hysteria2 فقط = أسرع عادة)
```
https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt
https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt
https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/Protocols/vless.txt
```

## 2) "VPN سريع" حقيقي = تستضيفه بنفسك (مشاريع GitHub)

| المشروع | ★ | ماذا يعطيك |
|---|---|---|
| `MHSanaei/3x-ui` | 48,806 | لوحة ويب كاملة لـ Xray: VLESS/Reality/VMess/Trojan + إدارة مستخدمين وحصص |
| `XTLS/Xray-core` | 42,419 | النواة نفسها (VLESS + Reality + XTLS-Vision = أفضل مقاومة للحجب) |
| `SagerNet/sing-box` | 39,368 | نواة حديثة، تدعم Hysteria2/TUIC + منافذ متعددة |
| `hiddify/Hiddify-Manager` | 9,434 | لوحة بنقرة واحدة على VPS، تدعم Hysteria2 تلقائيًا |
| `Gozargah/Marzban` | 7,484 | لوحة REST API حديثة (FastAPI) لمزوّدي الخدمة |

VPS رخيص (~3–5 $/شهر) + 3x-ui = عقدة خاصة سرعتها لا يشاركك فيها أحد، وهذا **أسرع بكثير** من أي كانفيغ مجاني.

## 3) العملاء (Clients)

| العميل | ★ | المنصّة |
|---|---|---|
| `clash-verge-rev/clash-verge-rev` | 154,749 | Windows / macOS / Linux |
| `2dust/v2rayN` | 119,395 | Windows |
| `2dust/v2rayNG` | 64,899 | Android |
| `MetaCubeX/mihomo` | 35,304 | نواة Clash (كل المنصات) |
| `MatsuriDayo/NekoBoxForAndroid` | 23,301 | Android (يدعم Hysteria2) |
| `KaringX/karing` | 15,804 | Android / iOS / Windows |

## 4) ملاحظات أمنية (مهمة)

1. **الكشف الكامل:** مشغّل العقدة يرى كل شيء (SNI، الوجهات، وحتى المحتوى إن ألغى TLS). لا تسجّل دخولًا للبنوك أو الحسابات الحساسة عبر عقدة مجهولة.
2. **"مجاني + سريع" نادرًا ما يجتمعان:** العقدة المجانية يستخدمها مئات الأشخاص → حِزم مشبعة. أعلى سرعة تحصل عليها من `hysteria2` على عقدة قريبة جغرافيًا وقليلة المستخدمين.
3. **العُمر قصير:** كثير من العُقد تموت في ساعات؛ لهذا تحتاج تحديثًا دوريًا (وهو ما يفعله `collector.py`) + اختبارًا حقيقيًا.
4. **التحقّق الحقيقي يحتاج ترافيك فعلي:** فحص TCP وحده لا يكفي (يظهر "حي" حتى لو كانت العقدة لا تمرّر شيئًا). الطريقة الصحيحة: تشغيل xray/sing-box محليًا وطلب `https://www.gstatic.com/generate_204` عبر socks، وقياس زمن الاستجابة والتنزيل.
5. **قانونيًا/ToS:** استخدام أو إعادة نشر كانفيغات قنوات عامة قد يخالف شروط الخدمة في بلدك أو شبكتك — المسؤولية عليك.
