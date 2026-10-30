-- =====================================================================
-- Migration 003: v3.1 Encrypted VIP Private Nodes, ABI-Aware APK Updates & Smart Auto-Failover
-- =====================================================================

CREATE TABLE IF NOT EXISTS vip_key_ring (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    key_hex TEXT NOT NULL,
    rotated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vip_servers (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT 'VLESS',
    config_uri TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vip_servers_enabled_prio ON vip_servers (enabled, priority DESC);

ALTER TABLE app_versions ADD COLUMN abi_assets_json TEXT NOT NULL DEFAULT '{}';

INSERT OR IGNORE INTO remote_config (config_key, config_value_json, requires_confirmation, description, updated_at)
VALUES
    ('auto_failover_enabled', 'true', 0, 'التبديل الذكي التلقائي خلال ثانيتين إلى أسرع سيرفر بديل عند سقوط النفق', '2026-10-30T00:00:00Z');
