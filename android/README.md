# bahrain-vpn — تطبيق الأندرويد الرسمي `v1` (العربية أساسية + الإنجليزية)

تطبيق **bahrain-vpn `v1`** (`versionCode = 1`, `versionName = "1.0"`) متكامل يعمل بمفرده بالكامل دون الحاجة لأي برنامج خارجي، بواجهة **ثنائية اللغة تعتمد العربية لغةً أساسية افتراضية (`RTL`) مع دعم كامل للغة الإنجليزية (`LTR`) وتبديل فوري بضغطة زر واحدة**: يزامن حزمة المرشّحات الموثّقة ببصمات `SHA-256` (`Top 500`)، يفحصها تسلسليًا على شبكة هاتفك الفعلية لاختيار **أفضل 50 سيرفرًا مخصّصًا (`Personalized Top 50`)** لكل من `Wi-Fi` و`Mobile Data` على حدة، ويتّصل بالـ VPN مباشرة عبر نفق أصلي (`Android VpnService` + `hev-socks5-tunnel` + `sing-box`).

## أبرز المميزات في الإصدار الرسمي `v1`

- **اللغة العربية أساسية + دعم كامل للإنجليزية (`AR Primary / EN Secondary`):** يبدأ التطبيق باللغة العربية وتخطيط `RTL` افتراضيًا، مع زر تبديل فوري (`EN / عربي`) في الشاشة الرئيسية وفي الإعدادات يحدّث جميع الشاشات والإشعارات وزر شريط الإشعارات العلوي (`Quick Settings Tile`) فورًا دون إعادة تشغيل.
- **اتصال VPN مدمج بالكامل ومنع تسرب `DNS/IPv6`:** نفق TUN أصلي مع `MapDNS` وتوجيه `tunnel-dns` داخل النفق (`detour="proxy"`) وحجز المسار `::/0`، ودعم كامل لبروتوكولات `VLESS`, `VMess`, `Trojan`, `Hysteria2`, `TUIC`, `Shadowsocks`.
- **ذكاء محلي مخصّص لكل شبكة (`Local Personalized Top 50`):** فحص تسلسلي آمن عبر النفق الحقيقي (`Concurrency = 1`) يعزل نتائج وترتيب `Wi-Fi` عن `Mobile Data` في قاعدة `SQLite WAL`.
- **متوافق مع Google Play Protect وموقّع بـ `RSA-4096 v1/v2/v3`:** خالٍ تمامًا من صلاحية `REQUEST_INSTALL_PACKAGES` وسلوك `Dropper`، ومفوّض لمتصفح النظام الرسمي عبر `HTTPS` مع نسخ بصمة `SHA-256`.
- **اتصال ذكي وتبديل تلقائي (`Smart Failover`) + `Kill Switch` + استثناء التطبيقات (`Split Tunneling`) + عُقد `VIP 💎` المشفّرة.**

## البنية البرمجية (`android/`)

```
android/
├── app/src/main/java/com/bahrain/vpnconfigs/      # تطبيق المشترك الرسمي v1 (com.bahrain.vpnconfigs)
│   ├── MainActivity.kt                            # Material 3 + التبديل اللحظي RTL/LTR (AR أساسية + EN)
│   ├── util/{AppI18n,UiMessages,Converters,AppDiag}.kt
│   ├── data/{Repo,Prefs,ClientDatabase}.kt        # تزامن Top 500 بـ SHA-256 + قاعدة SQLite WAL
│   ├── engine/{LocalServerIntelligence,SmartServerSelector,SecurityEvaluator,SingBox,Socks,Tester}.kt
│   ├── vpn/{BahrainVpnService,LeakProtectionEngine,KillSwitchController,ConnectionSecurityClassifier,SmartFailoverEngine,QuickTileService}.kt
│   ├── enterprise/{EnterpriseLicenseGuard,EnterpriseCrypto,AppUpdateManager,ClientDiagnosticsEngine}.kt
│   └── ui/{Screens,EnterpriseScreens,SecurityStatusScreen,FavoritesScreen,ServerHistoryScreen,PromoDialog,AppViewModel}.kt
├── admin/src/main/java/com/bahrain/vpnadmin/      # تطبيق المشرف المستقل v1 (com.bahrain.vpnadmin — AR/EN)
└── scripts/fetch-engines.sh                       # يجلب ويتحقق من بصمات SHA-256 لـ libsingbox.so + hev-socks5-tunnel.aar
```

## البناء والاختبار

```bash
cd android
bash scripts/fetch-engines.sh --all
./gradlew testReleaseUnitTest assembleRelease :admin:assembleRelease
```
