# bahrain-vpn — تطبيق VPN أندرويد متكامل

تطبيق **bahrain-vpn** متكامل يعمل بمفرده بالكامل دون الحاجة لأي برنامج خارجي: ينزّل السيرفرات الحيّة تلقائيًا من مستودع `oldman-552/vpn-configs`، يعرضها باسم موحّد **`bahrain-vpn #1`، `bahrain-vpn #2`…**، يفحص سرعتها على شبكة هاتفك، **ويتّصل بالـ VPN مباشرة بضغطة زر واحدة** عبر نفق أصلي (`Android VpnService` + `hev-socks5-tunnel` + `sing-box`).

## أبرز المميزات

- **اتصال VPN مدمج بالكامل:** لا حاجة لتطبيقات خارجية — نفق TUN أصلي بكتابة C/lwIP مع `MapDNS` لمنع تسريب DNS ودعم كامل لبروتوكولات `VLESS`, `VMess`, `Trojan`, `Hysteria2`, `TUIC`, `Shadowsocks`.
- **تسمية موحّدة (`bahrain-vpn`):** جميع السيرفرات داخل التطبيق وفي ملفات الاشتراك والتصدير تحمل اسم `bahrain-vpn`.
- **اتصال ذكي وتبديل تلقائي (Smart Parallel Failover):** يتحقّق من عمل الإنترنت فعليًا عند الاتصال وينتقل تلقائيًا لأسرع سيرفر شغّال إذا توقّف السيرفر الحالي دون هدم نفق الـ VPN، مع دعم انتقال الشبكة السلس بين Wi-Fi و 5G.
- **استثناء التطبيقات (Split Tunneling):** استثناء تطبيقات البنوك والخدمات المحلية من الـ VPN (أو قصر الـ VPN على تطبيقات محددة).
- **مراقبة حيّة وإشعار تفاعلي + زر شريط الإشعارات (Quick Settings Tile):** عدّاد مدة الاتصال، سرعة التنزيل والرفع اللحظية، إجمالي استهلاك البيانات، البينغ الحيّ، وعلم دولة الخروج مع الـ IP المحمي.
- **قائمة سيرفرات متكاملة:** بحث، فلترة حسب البروتوكول والمفضلة ⭐، فحص سريع (Ping) وفحص سرعة تنزيل، إضافة كانفيغات مخصّصة من الحافظة، وتصدير `best100.txt` / `sub.txt` / `config.txt`.

## البنية

```
android/
├── app/src/main/java/com/bahrain/vpnconfigs/
│   ├── MainActivity.kt            # Material 3 + RTL + 4 تبويبات + صلاحيات الـ VPN والإشعارات
│   ├── vpn/
│   │   ├── BahrainVpnService.kt   # نفق VpnService + hev-socks5-tunnel + sing-box + التبديل الذكي
│   │   ├── VpnState.kt            # الحالة التفاعلية المشتركة للإحصاءات الحيّة والسرعة
│   │   ├── QuickTileService.kt    # زر التشغيل السريع في شريط إشعارات أندرويد العلوي
│   │   └── InstalledApps.kt       # قراءة التطبيقات المثبّتة لميزة Split Tunneling
│   ├── engine/
│   │   ├── Converters.kt          # URI → outbound sing-box + التسمية الموحّدة bahrain-vpn
│   │   ├── Socks.kt               # فحص socks5h + TLS وقياس الزمن والسرعة وعنوان الخروج
│   │   ├── SingBox.kt             # إدارة عملية sing-box للفحص ولنفق الـ VPN
│   │   └── Tester.kt              # فحص متوازٍ آمن: فحص سريع (Ping) أو فحص سرعة شامل
│   ├── data/{Repo,Prefs}.kt       # جلب البيانات، الكاش المحلي، المفضلة، والإعدادات
│   ├── ui/{Theme,Screens,AppViewModel}.kt
│   └── work/RefreshWorker.kt      # تحديث القائمة الحيّة دوريًا في الخلفية
└── scripts/fetch-engines.sh       # ينزّل libsingbox.so + hev-socks5-tunnel.aar
```

## البناء

```bash
cd android
bash scripts/fetch-engines.sh --all
gradle assembleDebug assembleRelease
```
