# bahrain-vpn — تطبيق الأندرويد الرسمي `v2` (العربية أساسية + الإنجليزية)

تطبيق **bahrain-vpn `v2`** (`versionCode = 2`, `versionName = "2.0"`) متكامل يعمل بمفرده بالكامل دون الحاجة لأي برنامج خارجي، بواجهة **ثنائية اللغة تعتمد العربية لغةً أساسية افتراضية (`RTL`) مع دعم كامل للغة الإنجليزية (`LTR`) وتبديل فوري بضغطة زر واحدة**: يزامن حزمة المرشّحات الموثّقة ببصمات `SHA-256` (`Top 500` وقائمة `Iran Top 500` المجتمعية)، يفحصها تسلسليًا على شبكة هاتفك الفعلية لاختيار **أفضل 50 سيرفرًا مخصّصًا (`Personalized Top 50`)** لكل من `Wi-Fi` و`Mobile Data` على حدة، ويتّصل بالـ VPN مباشرة عبر نفق أصلي (`Android VpnService` + `hev-socks5-tunnel` + `sing-box`) مع دعم **مشاركة اتصال الـ VPN عبر الهوتسبوت بدون روت (`Rootless VPN Hotspot`)**.

## أبرز المميزات في الإصدار الرسمي `v2`

- **اللغة العربية أساسية + دعم كامل للإنجليزية (`AR Primary / EN Secondary`):** يبدأ التطبيق باللغة العربية وتخطيط `RTL` افتراضيًا، مع زر تبديل فوري (`EN / عربي`) في الشاشة الرئيسية وفي الإعدادات يحدّث جميع الشاشات والإشعارات وزر شريط الإشعارات العلوي (`Quick Settings Tile`) فورًا دون إعادة تشغيل.
- **اتصال VPN مدمج بالكامل ومنع تسرب `DNS/IPv6`:** نفق TUN أصلي مع `MapDNS` وتوجيه `tunnel-dns` داخل النفق (`detour="proxy"`) وحجز المسار `::/0`، ودعم كامل لبروتوكولات `VLESS`, `VMess`, `Trojan`, `Hysteria2`, `TUIC`, `Shadowsocks`, `SOCKS5`, `HTTP(S)`.
- **مشاركة اتصال الـ VPN عبر الهوتسبوت بدون روت (`Rootless VPN Hotspot`):** واجهة مستقلة (`نقطة اتصال الـ VPN`) تدعم مشاركة النفق المشفّر للأجهزة المتصلة بالهوتسبوت (`HTTP/HTTPS CONNECT` + `SOCKS5 TCP/UDP` + ملف إعداد تلقائي `/proxy.pac` + مصادقة اختيارية باسم مستخدم وكلمة مرور) مع إغلاق آمن صارم (`Fail-Closed`) عند انقطاع الـ VPN.
- **الفحص المجتمعي الطوعي وترتيب سيرفرات إيران الموثّقة (`Community VPN Verification — Iran Top 500`):** معطّل افتراضيًا بالكامل (`OFF`) ولا يعمل إلا بموافقة صريحة؛ يفحص السيرفرات محليًا بالتسلسل بدون تحويل الهاتف إلى بروكسي عام، ويتحقق من دولة الشبكة المباشرة (`IR`) دون GPS، ويتيح التحويل بضغطة واحدة إلى قائمة `Iran Top 500`.
- **ذكاء محلي مخصّص لكل شبكة (`Local Personalized Top 50`):** فحص تسلسلي آمن عبر النفق الحقيقي (`Concurrency = 1`) يعزل نتائج وترتيب `Wi-Fi` عن `Mobile Data` في قاعدة `SQLite WAL`.
- **متوافق مع Google Play Protect وموقّع بـ `RSA-4096 v1/v2/v3`:** خالٍ تمامًا من صلاحية `REQUEST_INSTALL_PACKAGES` وسلوك `Dropper`، ومفوّض لمتصفح النظام الرسمي عبر `HTTPS` مع نسخ بصمة `SHA-256`.
- **استثناء تلقائي لنطاقات `.ir` و `.ایران` من الـ VPN (مفعّل افتراضياً + زر تحكم):** أي اتصال لموقع أو سيرفر ينتهي بـ `.ir` أو `.ایران` يمرّ مباشرة عبر إنترنت جهازك المحلي (`direct` + `direct-dns` + `SNI sniff`) دون المرور على سيرفر الـ VPN، مع إمكانية التفعيل أو الإيقاف الفوري من الإعدادات أو شاشة التحكم بالتطبيقات.
- **اتصال ذكي وتبديل تلقائي (`Smart Failover`) + `Kill Switch` + استثناء التطبيقات (`Split Tunneling`) + عُقد `VIP 💎` المشفّرة.**

## البنية البرمجية (`android/`)

```
android/
├── app/src/main/java/com/bahrain/vpnconfigs/      # تطبيق المشترك الرسمي v2 (com.bahrain.vpnconfigs)
│   ├── MainActivity.kt                            # Material 3 + التبديل اللحظي RTL/LTR (AR أساسية + EN)
│   ├── util/{AppI18n,UiMessages,Converters,AppDiag}.kt
│   ├── data/{Repo,Prefs,ClientDatabase}.kt        # تزامن Top 500 و Iran Top 500 بـ SHA-256 + SQLite WAL v4
│   ├── hotspot/VpnHotspotManager.kt               # مشاركة VPN عبر الهوتسبوت بدون روت (HTTP/SOCKS5/PAC + Fail-Closed)
│   ├── community/CommunityTestingManager.kt       # الفحص المجتمعي الطوعي الموثّق بدون بروكسي وخصوصية صارمة
│   ├── engine/{LocalServerIntelligence,SmartServerSelector,SecurityEvaluator,SingBox,Socks,Tester}.kt
│   ├── vpn/{BahrainVpnService,LeakProtectionEngine,KillSwitchController,ConnectionSecurityClassifier,SmartFailoverEngine,QuickTileService}.kt
│   ├── enterprise/{EnterpriseLicenseGuard,EnterpriseCrypto,AppUpdateManager,ClientDiagnosticsEngine}.kt
│   └── ui/{Screens,VpnHotspotScreen,CommunityTestingScreen,EnterpriseScreens,SecurityStatusScreen,FavoritesScreen,ServerHistoryScreen,PromoDialog,AppViewModel}.kt
├── admin/src/main/java/com/bahrain/vpnadmin/      # تطبيق المشرف المستقل v2 (com.bahrain.vpnadmin — AR/EN)
└── scripts/fetch-engines.sh                       # يجلب ويتحقق من بصمات SHA-256 لـ libsingbox.so + hev-socks5-tunnel.aar
```

## البناء والاختبار

```bash
cd android
bash scripts/fetch-engines.sh --all
./gradlew testReleaseUnitTest assembleRelease :admin:assembleRelease
```
