-- =====================================================================
-- Migration 002: Default RBAC Roles & Enterprise Remote Config Defaults
-- =====================================================================
INSERT OR IGNORE INTO admin_roles (id, role_name, permissions_json, created_at)
VALUES
    ('role_super_admin', 'SUPER_ADMIN', '["*"]', '2026-10-30T00:00:00Z'),
    ('role_operator', 'OPERATOR', '["users.read","users.write","sessions.manage","servers.read","diagnostics.read"]', '2026-10-30T00:00:00Z'),
    ('role_auditor', 'AUDITOR', '["users.read","servers.read","logs.read","audit.read","ai.read"]', '2026-10-30T00:00:00Z');

INSERT OR IGNORE INTO remote_config (config_key, config_value_json, requires_confirmation, description, updated_at)
VALUES
    ('auth_require_account', 'false', 1, 'تفعيل إلزامية تسجيل الدخول قبل تشغيل نفق VPN في تطبيق المستخدم', '2026-10-30T00:00:00Z'),
    ('maintenance_mode', '{"enabled":false,"message_ar":"النظام في وضع الصيانة المجدولة","message_en":"System under scheduled maintenance"}', 1, 'وضع الصيانة العام', '2026-10-30T00:00:00Z'),
    ('min_app_version_code', '1', 1, 'الحد الأدنى لنسخة تطبيق المستخدم المسموح لها بالاتصال', '2026-10-30T00:00:00Z'),
    ('default_device_limit', '1', 0, 'عدد الأجهزة الافتراضي لكل حساب جديد (1 = جهاز واحد)', '2026-10-30T00:00:00Z'),
    ('auto_block_on_device_violation', 'false', 1, 'حظر الحساب تلقائيًا عند محاولة دخول جهاز غير مصرح به', '2026-10-30T00:00:00Z'),
    ('trial_duration_hours', '48', 0, 'مدة التجربة المجانية بالساعات المتتالية (48 ساعة)', '2026-10-30T00:00:00Z'),
    ('heartbeat_interval_sec', '60', 0, 'الفاصل الزمني لنبضات الجلسة وتحديث الحالة بالثواني', '2026-10-30T00:00:00Z'),
    ('speed_test_endpoints', '{"download_url":"https://speed.cloudflare.com/__down?bytes=1000000","upload_url":"https://speed.cloudflare.com/__up","ping_url":"https://www.gstatic.com/generate_204"}', 0, 'نقاط قياس السرعة عبر النفق الفعلي بدون كاش', '2026-10-30T00:00:00Z'),
    ('disabled_server_ids', '[]', 1, 'معرّفات السيرفرات المعطّلة عن بُعد من المشرف', '2026-10-30T00:00:00Z'),
    ('default_server_id', '""', 0, 'معرّف السيرفر الافتراضي الموصى به', '2026-10-30T00:00:00Z'),
    ('data_retention_days', '90', 0, 'فترة الاحتفاظ بسجلات التشخيص والاتصال بالأيام', '2026-10-30T00:00:00Z');
