-- =====================================================================
-- Migration 001: Normalized Relational Schema (All 21 Enterprise Tables)
-- =====================================================================
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_roles (
    id TEXT PRIMARY KEY,
    role_name TEXT NOT NULL UNIQUE,
    permissions_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret_enc TEXT NOT NULL DEFAULT '',
    totp_enabled INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1)),
    role_id TEXT NOT NULL REFERENCES admin_roles(id) ON DELETE RESTRICT,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    last_login_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    envelope_salt_hex TEXT NOT NULL,
    envelope_ciphertext_b64 TEXT NOT NULL DEFAULT '',
    account_status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (account_status IN ('ACTIVE','FREE_TRIAL','EXPIRED','SUSPENDED','BLOCKED','DISABLED')),
    subscription_type TEXT NOT NULL DEFAULT 'MONTHLY'
        CHECK (subscription_type IN ('FREE_TRIAL','DAILY','WEEKLY','MONTHLY','THREE_MONTHS','SIX_MONTHS','YEARLY','LIFETIME')),
    subscription_start TEXT,
    subscription_expiration TEXT,
    device_limit INTEGER NOT NULL DEFAULT 1 CHECK (device_limit >= 1 AND device_limit <= 50),
    trial_activation_date TEXT,
    last_login TEXT,
    last_activity TEXT,
    total_sessions INTEGER NOT NULL DEFAULT 0,
    total_data_usage INTEGER NOT NULL DEFAULT 0,
    total_download INTEGER NOT NULL DEFAULT 0,
    total_upload INTEGER NOT NULL DEFAULT 0,
    session_revoked_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_status ON users(account_status);
CREATE INDEX IF NOT EXISTS idx_users_expiration ON users(subscription_expiration);

CREATE TABLE IF NOT EXISTS user_subscriptions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subscription_type TEXT NOT NULL
        CHECK (subscription_type IN ('FREE_TRIAL','DAILY','WEEKLY','MONTHLY','THREE_MONTHS','SIX_MONTHS','YEARLY','LIFETIME')),
    starts_at TEXT NOT NULL,
    expires_at TEXT,
    is_current INTEGER NOT NULL DEFAULT 1 CHECK (is_current IN (0, 1)),
    created_by_admin_id TEXT REFERENCES admin_users(id) ON DELETE SET NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_subs_user ON user_subscriptions(user_id, is_current);

CREATE TABLE IF NOT EXISTS trial_activations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    activated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    extended_hours INTEGER NOT NULL DEFAULT 0,
    converted_to_paid INTEGER NOT NULL DEFAULT 0 CHECK (converted_to_paid IN (0, 1)),
    initial_device_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','EXPIRED','CONVERTED','REVOKED'))
);

CREATE TABLE IF NOT EXISTS bandwidth_limits (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    auto_block_on_violation INTEGER NOT NULL DEFAULT 0 CHECK (auto_block_on_violation IN (0, 1)),
    max_download_kbps INTEGER NOT NULL DEFAULT 0 CHECK (max_download_kbps >= 0),
    max_upload_kbps INTEGER NOT NULL DEFAULT 0 CHECK (max_upload_kbps >= 0),
    max_total_kbps INTEGER NOT NULL DEFAULT 0 CHECK (max_total_kbps >= 0),
    max_daily_mb INTEGER NOT NULL DEFAULT 0 CHECK (max_daily_mb >= 0),
    max_monthly_mb INTEGER NOT NULL DEFAULT 0 CHECK (max_monthly_mb >= 0),
    max_concurrent_connections INTEGER NOT NULL DEFAULT 1 CHECK (max_concurrent_connections >= 1),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_install_id TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    manufacturer TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    android_version TEXT NOT NULL DEFAULT '',
    app_version TEXT NOT NULL DEFAULT '',
    registration_date TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    device_status TEXT NOT NULL DEFAULT 'AUTHORIZED'
        CHECK (device_status IN ('AUTHORIZED','REVOKED','BLOCKED','REPLACED')),
    UNIQUE(user_id, device_install_id)
);

CREATE INDEX IF NOT EXISTS idx_user_devices_user ON user_devices(user_id, device_status);

CREATE TABLE IF NOT EXISTS device_violations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attempted_install_id TEXT NOT NULL,
    attempted_device_name TEXT NOT NULL DEFAULT '',
    attempted_model TEXT NOT NULL DEFAULT '',
    auto_blocked INTEGER NOT NULL DEFAULT 0 CHECK (auto_blocked IN (0, 1)),
    violation_reason TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    resolved_at TEXT,
    resolved_by_admin_id TEXT REFERENCES admin_users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_device_violations_user ON device_violations(user_id, occurred_at);

CREATE TABLE IF NOT EXISTS login_attempts (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    device_install_id TEXT NOT NULL DEFAULT '',
    ip_hash TEXT NOT NULL DEFAULT '',
    succeeded INTEGER NOT NULL CHECK (succeeded IN (0, 1)),
    failure_reason TEXT NOT NULL DEFAULT '',
    attempted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time ON login_attempts(username, attempted_at);

CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    server_name TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL,
    config_uri TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ONLINE' CHECK (status IN ('ONLINE','DEGRADED','OFFLINE','DISABLED')),
    quality_tier TEXT NOT NULL DEFAULT 'GOOD'
        CHECK (quality_tier IN ('EXCELLENT','VERY_GOOD','GOOD','AVERAGE','POOR','OFFLINE')),
    quality_score REAL NOT NULL DEFAULT 0.0,
    active_sessions INTEGER NOT NULL DEFAULT 0,
    cpu_usage REAL NOT NULL DEFAULT 0.0,
    ram_usage REAL NOT NULL DEFAULT 0.0,
    bandwidth_mbps REAL NOT NULL DEFAULT 0.0,
    ping_ms INTEGER NOT NULL DEFAULT 0,
    jitter_ms REAL NOT NULL DEFAULT 0.0,
    packet_loss_pct REAL NOT NULL DEFAULT 0.0,
    uptime_pct REAL NOT NULL DEFAULT 100.0,
    stability_runs INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    last_health_check TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_servers_status_score ON servers(enabled, status, quality_score DESC);

CREATE TABLE IF NOT EXISTS server_health (
    id TEXT PRIMARY KEY,
    server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    checked_at TEXT NOT NULL,
    is_online INTEGER NOT NULL CHECK (is_online IN (0, 1)),
    ping_ms INTEGER NOT NULL DEFAULT 0,
    jitter_ms REAL NOT NULL DEFAULT 0.0,
    packet_loss_pct REAL NOT NULL DEFAULT 0.0,
    download_kbps REAL NOT NULL DEFAULT 0.0,
    cpu_usage REAL NOT NULL DEFAULT 0.0,
    ram_usage REAL NOT NULL DEFAULT 0.0,
    active_sessions INTEGER NOT NULL DEFAULT 0,
    quality_score REAL NOT NULL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_server_health_server_time ON server_health(server_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS user_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
    server_id TEXT REFERENCES servers(id) ON DELETE SET NULL,
    vpn_protocol TEXT NOT NULL,
    connection_start TEXT NOT NULL,
    connection_end TEXT,
    session_duration INTEGER NOT NULL DEFAULT 0,
    session_status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (session_status IN ('ACTIVE','CLOSED','EXPIRED','REVOKED','TERMINATED')),
    reconnection_count INTEGER NOT NULL DEFAULT 0,
    total_download INTEGER NOT NULL DEFAULT 0,
    total_upload INTEGER NOT NULL DEFAULT 0,
    current_down_bps INTEGER NOT NULL DEFAULT 0,
    current_up_bps INTEGER NOT NULL DEFAULT 0,
    ping_ms INTEGER NOT NULL DEFAULT 0,
    jitter_ms REAL NOT NULL DEFAULT 0.0,
    packet_loss_pct REAL NOT NULL DEFAULT 0.0,
    last_heartbeat TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(session_status, last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id, connection_start DESC);

CREATE TABLE IF NOT EXISTS data_usage (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    usage_date TEXT NOT NULL,
    download_bytes INTEGER NOT NULL DEFAULT 0,
    upload_bytes INTEGER NOT NULL DEFAULT 0,
    sessions_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(user_id, usage_date)
);

CREATE INDEX IF NOT EXISTS idx_data_usage_user_date ON data_usage(user_id, usage_date DESC);

CREATE TABLE IF NOT EXISTS speed_tests (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    device_id TEXT REFERENCES user_devices(id) ON DELETE SET NULL,
    server_id TEXT REFERENCES servers(id) ON DELETE SET NULL,
    tested_at TEXT NOT NULL,
    download_kbps REAL NOT NULL DEFAULT 0.0,
    upload_kbps REAL NOT NULL DEFAULT 0.0,
    ping_ms INTEGER NOT NULL DEFAULT 0,
    jitter_ms REAL NOT NULL DEFAULT 0.0,
    packet_loss_pct REAL NOT NULL DEFAULT 0.0,
    avg_speed_kbps REAL NOT NULL DEFAULT 0.0,
    max_speed_kbps REAL NOT NULL DEFAULT 0.0,
    min_speed_kbps REAL NOT NULL DEFAULT 0.0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    via_vpn_tunnel INTEGER NOT NULL DEFAULT 1 CHECK (via_vpn_tunnel IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_speed_tests_time ON speed_tests(tested_at DESC);

CREATE TABLE IF NOT EXISTS network_tests (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    device_id TEXT REFERENCES user_devices(id) ON DELETE SET NULL,
    server_id TEXT REFERENCES servers(id) ON DELETE SET NULL,
    tested_at TEXT NOT NULL,
    dns_leak INTEGER NOT NULL DEFAULT 0 CHECK (dns_leak IN (0, 1)),
    ip_leak INTEGER NOT NULL DEFAULT 0 CHECK (ip_leak IN (0, 1)),
    webrtc_leak INTEGER NOT NULL DEFAULT 0 CHECK (webrtc_leak IN (0, 1)),
    dns_resolution_ms INTEGER NOT NULL DEFAULT 0,
    tls_valid INTEGER NOT NULL DEFAULT 1 CHECK (tls_valid IN (0, 1)),
    tunnel_status TEXT NOT NULL DEFAULT 'CONNECTED',
    mtu_bytes INTEGER NOT NULL DEFAULT 1500,
    packet_loss_pct REAL NOT NULL DEFAULT 0.0,
    jitter_ms REAL NOT NULL DEFAULT 0.0,
    stability_score REAL NOT NULL DEFAULT 100.0,
    target_url TEXT NOT NULL DEFAULT '',
    response_ms INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS connection_logs (
    id TEXT PRIMARY KEY,
    logged_at TEXT NOT NULL,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    device_id TEXT REFERENCES user_devices(id) ON DELETE SET NULL,
    session_id TEXT REFERENCES user_sessions(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    error_code TEXT NOT NULL DEFAULT '',
    error_description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'INFO' CHECK (severity IN ('INFO','WARNING','ERROR','CRITICAL'))
);

CREATE INDEX IF NOT EXISTS idx_connection_logs_time_type ON connection_logs(logged_at DESC, event_type);

CREATE TABLE IF NOT EXISTS app_versions (
    id TEXT PRIMARY KEY,
    target_app TEXT NOT NULL DEFAULT 'USER' CHECK (target_app IN ('USER','ADMIN')),
    version_code INTEGER NOT NULL,
    version_name TEXT NOT NULL,
    release_notes TEXT NOT NULL DEFAULT '',
    release_date TEXT NOT NULL,
    mandatory INTEGER NOT NULL DEFAULT 0 CHECK (mandatory IN (0, 1)),
    min_supported_code INTEGER NOT NULL DEFAULT 1,
    apk_url TEXT NOT NULL,
    apk_sha256 TEXT NOT NULL,
    signing_cert_sha256 TEXT NOT NULL DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    UNIQUE(target_app, version_code)
);

CREATE TABLE IF NOT EXISTS app_crashes (
    id TEXT PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    app_version TEXT NOT NULL,
    android_version TEXT NOT NULL,
    device_model TEXT NOT NULL,
    issue_type TEXT NOT NULL CHECK (issue_type IN ('CRASH','ANR','TUNNEL_ERROR','DNS_ERROR','API_ERROR','STARTUP')),
    startup_time_ms INTEGER NOT NULL DEFAULT 0,
    memory_mb REAL NOT NULL DEFAULT 0.0,
    error_summary TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_app_crashes_version ON app_crashes(app_version, occurred_at DESC);

CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    event_category TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'INFO' CHECK (severity IN ('INFO','WARNING','HIGH','CRITICAL')),
    title_ar TEXT NOT NULL,
    title_en TEXT NOT NULL,
    body_ar TEXT NOT NULL,
    body_en TEXT NOT NULL,
    target_user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    is_read INTEGER NOT NULL DEFAULT 0 CHECK (is_read IN (0, 1)),
    acknowledged_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(is_read, created_at DESC);

CREATE TABLE IF NOT EXISTS remote_config (
    config_key TEXT PRIMARY KEY,
    config_value_json TEXT NOT NULL,
    requires_confirmation INTEGER NOT NULL DEFAULT 0 CHECK (requires_confirmation IN (0, 1)),
    description TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    updated_by_admin_id TEXT REFERENCES admin_users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id TEXT PRIMARY KEY,
    logged_at TEXT NOT NULL,
    admin_id TEXT REFERENCES admin_users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL DEFAULT '',
    before_json TEXT NOT NULL DEFAULT '{}',
    after_json TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL DEFAULT '',
    entry_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_time ON admin_audit_logs(logged_at DESC);
