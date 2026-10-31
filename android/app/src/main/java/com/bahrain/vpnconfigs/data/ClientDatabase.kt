// =====================================================================
// ClientDatabase.kt — قاعدة البيانات المحلية المدمجة SQLite (WAL + Migrations)
// لتخزين سجل الجلسات، المفضلة المتقدمة، القياسات المحلية للسيرفرات، وأحداث الحماية.
//
// ضمانات الخصوصية والأمان (Privacy by Design):
//   • تعتمد على المعرّف المستقر الآمن (serverId = SHA-256 canonical fingerprint).
//   • لا تخزّن أي كلمات مرور أو مفاتيح خاصة أو روابط إعداد كاملة تحتوي على بيانات اعتماد.
//   • تدعم الترحيل السلس للإصدارات، الفهرسة السريعة، الصفحات (Pagination)، وسياسات الاحتفاظ.
// =====================================================================
package com.bahrain.vpnconfigs.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import com.bahrain.vpnconfigs.engine.Converters
import com.bahrain.vpnconfigs.util.tr
import kotlin.math.abs
import kotlin.math.max

enum class HistorySortOrder(val key: String, val labelAr: String, val labelEn: String) {
    RECENT("RECENT", "الأحدث", "Newest"),
    BEST_PERFORMANCE("BEST_PERFORMANCE", "الأعلى سرعة", "Top Speed"),
    LOWEST_LATENCY("LOWEST_LATENCY", "الأقل تأخيرًا", "Lowest Ping"),
    LONGEST_DURATION("LONGEST_DURATION", "الأطول مدة", "Longest");

    val displayLabel: String
        get() = tr(labelAr, labelEn)

    companion object {
        fun fromKey(raw: String?): HistorySortOrder =
            entries.firstOrNull { it.key.equals(raw?.trim(), ignoreCase = true) } ?: RECENT
    }
}

enum class FavoriteSortOrder(val key: String, val labelAr: String, val labelEn: String) {
    RECENT("RECENT", "الأحدث إضافة", "Recently Added"),
    NAME("NAME", "الاسم", "Name"),
    GROUP("GROUP", "المجموعة", "Group"),
    PERFORMANCE("PERFORMANCE", "الأفضل أداءً", "Best Performance");

    val displayLabel: String
        get() = tr(labelAr, labelEn)

    companion object {
        fun fromKey(raw: String?): FavoriteSortOrder =
            entries.firstOrNull { it.key.equals(raw?.trim(), ignoreCase = true) } ?: RECENT
    }
}

data class ServerSessionRecord(
    val id: Long,
    val serverId: String,
    val serverLabel: String,
    val maskedEndpoint: String,
    val protocol: String,
    val country: String,
    val connectedAtMs: Long,
    val disconnectedAtMs: Long,
    val durationSec: Long,
    val success: Boolean,
    val avgLatencyMs: Long,
    val jitterMs: Double,
    val packetLossPct: Double,
    val peakDownloadBps: Long,
    val peakUploadBps: Long,
    val totalDownBytes: Long,
    val totalUpBytes: Long,
    val failureReason: String,
    val networkType: String,
)

data class FavoriteServerRecord(
    val serverId: String,
    val customName: String,
    val defaultLabel: String,
    val groupName: String,
    val protocol: String,
    val maskedEndpoint: String,
    val country: String,
    val sortOrder: Int,
    val addedAtMs: Long,
    val updatedAtMs: Long,
) {
    val displayName: String
        get() = customName.ifBlank { defaultLabel.ifBlank { "bahrain-vpn (${serverId.take(6)})" } }
}

data class LocalServerTelemetry(
    val serverId: String,
    val attempts: Int = 0,
    val successes: Int = 0,
    val consecutiveFailures: Int = 0,
    val lastFailureAtMs: Long = 0L,
    val lastFailureCategory: String = "",
    val lastSuccessAtMs: Long = 0L,
    val avgEstablishMs: Long = 0L,
    val ewmaLatencyMs: Double = 0.0,
    val latencyVarianceMs2: Double = 0.0,
    val ewmaJitterMs: Double = 0.0,
    val ewmaPacketLossPct: Double = 0.0,
    val bestDownloadKbps: Double = 0.0,
    val bestUploadKbps: Double = 0.0,
    val wifiSuccesses: Int = 0,
    val cellularSuccesses: Int = 0,
    val recentTrendDelta: Double = 0.0,
) {
    val successRate: Double
        get() = if (attempts > 0) successes.toDouble() / attempts.toDouble() else 0.0
}

data class ProtectionEventRecord(
    val id: Long,
    val eventAtMs: Long,
    val category: String,
    val titleAr: String,
    val detailAr: String,
)

/**
 * ملف تعريف الشبكة المستقل للترتيب المخصّص وسجل القياسات المحلية (القسم 5):
 * لا يُفترض أبدًا أن السيرفر السريع على Wi-Fi سيعمل بنفس الكفاءة على بيانات الجوال.
 */
enum class ScanNetworkProfile(val code: String, val labelAr: String, val labelEn: String) {
    WIFI("WIFI", "شبكة Wi‑Fi", "Wi-Fi"),
    MOBILE_DATA("MOBILE_DATA", "بيانات الجوال", "Mobile Data");

    val displayLabel: String
        get() = tr(labelAr, labelEn)

    companion object {
        fun fromTransportCode(raw: String?): ScanNetworkProfile {
            val u = raw?.trim()?.uppercase().orEmpty()
            return if (u.contains("CELL") || u.contains("MOBILE")) MOBILE_DATA else WIFI
        }
    }
}

enum class LocalPoolTier(val code: String, val labelAr: String, val labelEn: String) {
    TOP_50("TOP_50", "أفضل 50 للشبكة", "Network Top 50"),
    BACKUP_POOL("BACKUP_POOL", "الاحتياطي المؤهّل", "Qualified Backup"),
    CANDIDATE_ONLY("CANDIDATE_ONLY", "مرشّح غير مفحوص محليًا", "Untested Candidate");

    val displayLabel: String
        get() = tr(labelAr, labelEn)

    companion object {
        fun fromCode(raw: String?): LocalPoolTier =
            entries.firstOrNull { it.code.equals(raw?.trim(), ignoreCase = true) } ?: CANDIDATE_ONLY
    }
}

data class ScanMeasurementSample(
    val id: Long = 0L,
    val serverId: String,
    val configFingerprint: String,
    val networkProfile: ScanNetworkProfile,
    val scanMode: String,
    val scannedAtMs: Long,
    val success: Boolean,
    val establishMs: Long,
    val latencyMs: Long,
    val jitterMs: Double,
    val packetLossPct: Double,
    val throughputKbps: Double,
    val stabilityScore: Double,
    val personalizedScore: Double,
    val failureReason: String = "",
)

data class NetworkServerProfileStats(
    val serverId: String,
    val networkProfile: ScanNetworkProfile,
    val configFingerprint: String,
    val lastSuccessfulConnectionMs: Long = 0L,
    val lastScanAtMs: Long = 0L,
    val scanCount: Int = 0,
    val successCount: Int = 0,
    val failureCount: Int = 0,
    val consecutiveFailures: Int = 0,
    val connectionSuccessRate: Double = 0.0,
    val latestEstablishMs: Long = 0L,
    val latestLatencyMs: Long = 0L,
    val ewmaLatencyMs: Double = 0.0,
    val latestJitterMs: Double = 0.0,
    val ewmaJitterMs: Double = 0.0,
    val latestPacketLossPct: Double = 0.0,
    val ewmaPacketLossPct: Double = 0.0,
    val latestThroughputKbps: Double = 0.0,
    val bestThroughputKbps: Double = 0.0,
    val stabilityScore: Double = 0.0,
    val personalizedScore: Double = 0.0,
) {
    val isQualifiedLocally: Boolean
        get() = successCount >= 1 && consecutiveFailures < 3 && latestLatencyMs > 0L && latestPacketLossPct < 60.0
}

data class PersonalizedRankEntry(
    val networkProfile: ScanNetworkProfile,
    val serverId: String,
    val configFingerprint: String,
    val poolTier: LocalPoolTier,
    val rankPosition: Int,
    val personalizedScore: Double,
    val stabilityScore: Double,
    val updatedAtMs: Long,
)

data class RankingHistorySnapshotRow(
    val id: Long,
    val scanBatchId: String,
    val rankedAtMs: Long,
    val networkProfile: ScanNetworkProfile,
    val scanMode: String,
    val serverId: String,
    val poolTier: LocalPoolTier,
    val rankPosition: Int,
    val personalizedScore: Double,
    val stabilityScore: Double,
)

data class CommunityTestReportRecord(
    val id: Long = 0L,
    val reportId: String,
    val serverId: String,
    val configFingerprint: String,
    val protocol: String,
    val testedAtMs: Long,
    val success: Boolean,
    val handshakeMs: Long,
    val latencyMs: Long,
    val downloadKbps: Double,
    val stabilityScore: Double,
    val dnsOk: Boolean,
    val tcpOk: Boolean,
    val udpOk: Boolean,
    val failureReason: String,
    val verifiedCountry: String,
    val countryConfidence: String,
    val vpnInterference: Boolean,
    val networkTransport: String,
    val submitted: Boolean = false,
    val submittedAtMs: Long = 0L,
)

data class CommunityReportStatsSummary(
    val totalTested: Int = 0,
    val totalSuccess: Int = 0,
    val verifiedIranCount: Int = 0,
    val pendingUploadCount: Int = 0,
    val submittedCount: Int = 0,
)

class ClientDatabase private constructor(ctx: Context) :
    SQLiteOpenHelper(ctx.applicationContext, DB_NAME, null, DB_VERSION) {

    companion object {
        const val DB_NAME = "bahrain_vpn_client.db"
        const val DB_VERSION = 4

        @Volatile
        private var instance: ClientDatabase? = null

        fun getInstance(ctx: Context): ClientDatabase =
            instance ?: synchronized(this) {
                instance ?: ClientDatabase(ctx.applicationContext).also { instance = it }
            }
    }

    private val lock = Any()

    override fun onConfigure(db: SQLiteDatabase) {
        super.onConfigure(db)
        db.setForeignKeyConstraintsEnabled(true)
        runCatching { db.enableWriteAheadLogging() }
    }

    override fun onCreate(db: SQLiteDatabase) {
        createSchemaV1(db)
        upgradeToV2(db)
        upgradeToV3(db)
        upgradeToV4(db)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 1) {
            createSchemaV1(db)
        }
        if (oldVersion < 2 && newVersion >= 2) {
            upgradeToV2(db)
        }
        if (oldVersion < 3 && newVersion >= 3) {
            upgradeToV3(db)
        }
        if (oldVersion < 4 && newVersion >= 4) {
            upgradeToV4(db)
        }
    }

    private fun createSchemaV1(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS connection_history (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id          TEXT NOT NULL,
                server_label       TEXT NOT NULL,
                masked_endpoint    TEXT NOT NULL,
                protocol           TEXT NOT NULL,
                country            TEXT NOT NULL DEFAULT '',
                connected_at_ms    INTEGER NOT NULL,
                disconnected_at_ms INTEGER NOT NULL DEFAULT 0,
                duration_sec       INTEGER NOT NULL DEFAULT 0,
                success            INTEGER NOT NULL DEFAULT 1,
                avg_latency_ms     INTEGER NOT NULL DEFAULT 0,
                jitter_ms          REAL NOT NULL DEFAULT 0.0,
                packet_loss_pct    REAL NOT NULL DEFAULT 0.0,
                peak_download_bps  INTEGER NOT NULL DEFAULT 0,
                peak_upload_bps    INTEGER NOT NULL DEFAULT 0,
                total_down_bytes   INTEGER NOT NULL DEFAULT 0,
                total_up_bytes     INTEGER NOT NULL DEFAULT 0,
                failure_reason     TEXT NOT NULL DEFAULT '',
                network_type       TEXT NOT NULL DEFAULT 'UNKNOWN'
            );
            """.trimIndent()
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_hist_connected_at ON connection_history(connected_at_ms DESC);")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_hist_server_id ON connection_history(server_id);")
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_hist_perf ON connection_history(peak_download_bps DESC, avg_latency_ms ASC);")

        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS favorite_servers (
                server_id       TEXT PRIMARY KEY,
                custom_name     TEXT NOT NULL DEFAULT '',
                default_label   TEXT NOT NULL DEFAULT '',
                group_name      TEXT NOT NULL DEFAULT 'عام',
                protocol        TEXT NOT NULL DEFAULT '',
                masked_endpoint TEXT NOT NULL DEFAULT '',
                country         TEXT NOT NULL DEFAULT '',
                sort_order      INTEGER NOT NULL DEFAULT 0,
                added_at_ms     INTEGER NOT NULL,
                updated_at_ms   INTEGER NOT NULL
            );
            """.trimIndent()
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_fav_group ON favorite_servers(group_name, sort_order ASC);")

        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS local_server_telemetry (
                server_id             TEXT PRIMARY KEY,
                attempts              INTEGER NOT NULL DEFAULT 0,
                successes             INTEGER NOT NULL DEFAULT 0,
                consecutive_failures  INTEGER NOT NULL DEFAULT 0,
                last_failure_at_ms    INTEGER NOT NULL DEFAULT 0,
                last_failure_category TEXT NOT NULL DEFAULT '',
                last_success_at_ms    INTEGER NOT NULL DEFAULT 0,
                avg_establish_ms      INTEGER NOT NULL DEFAULT 0,
                ewma_latency_ms       REAL NOT NULL DEFAULT 0.0,
                latency_variance_ms2  REAL NOT NULL DEFAULT 0.0,
                ewma_jitter_ms        REAL NOT NULL DEFAULT 0.0,
                ewma_packet_loss_pct  REAL NOT NULL DEFAULT 0.0,
                best_download_kbps    REAL NOT NULL DEFAULT 0.0,
                best_upload_kbps      REAL NOT NULL DEFAULT 0.0,
                wifi_successes        INTEGER NOT NULL DEFAULT 0,
                cellular_successes    INTEGER NOT NULL DEFAULT 0,
                recent_trend_delta    REAL NOT NULL DEFAULT 0.0
            );
            """.trimIndent()
        )
    }

    private fun upgradeToV2(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS protection_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                event_at_ms INTEGER NOT NULL,
                category    TEXT NOT NULL,
                title_ar    TEXT NOT NULL,
                detail_ar   TEXT NOT NULL DEFAULT ''
            );
            """.trimIndent()
        )
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_prot_events_at ON protection_events(event_at_ms DESC);")
    }

    private fun upgradeToV3(db: SQLiteDatabase) {
        // 1) Append-only historical scan measurements (preserves latency, jitter, packet-loss, throughput history)
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS server_scan_measurements (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id           TEXT NOT NULL,
                config_fingerprint  TEXT NOT NULL,
                network_profile     TEXT NOT NULL,
                scan_mode           TEXT NOT NULL,
                scanned_at_ms       INTEGER NOT NULL,
                success             INTEGER NOT NULL DEFAULT 0,
                establish_ms        INTEGER NOT NULL DEFAULT 0,
                latency_ms          INTEGER NOT NULL DEFAULT 0,
                jitter_ms           REAL NOT NULL DEFAULT 0.0,
                packet_loss_pct     REAL NOT NULL DEFAULT 0.0,
                throughput_kbps     REAL NOT NULL DEFAULT 0.0,
                stability_score     REAL NOT NULL DEFAULT 0.0,
                personalized_score  REAL NOT NULL DEFAULT 0.0,
                failure_reason      TEXT NOT NULL DEFAULT ''
            );
            """.trimIndent()
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_scan_meas_srv_net ON server_scan_measurements(server_id, network_profile, scanned_at_ms DESC);"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_scan_meas_net_time ON server_scan_measurements(network_profile, scanned_at_ms DESC);"
        )

        // 2) Per-network-profile aggregated server intelligence (WIFI vs MOBILE_DATA kept strictly separate)
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS network_server_stats (
                server_id                      TEXT NOT NULL,
                network_profile                TEXT NOT NULL,
                config_fingerprint             TEXT NOT NULL DEFAULT '',
                last_successful_connection_ms  INTEGER NOT NULL DEFAULT 0,
                last_scan_at_ms                INTEGER NOT NULL DEFAULT 0,
                scan_count                     INTEGER NOT NULL DEFAULT 0,
                success_count                  INTEGER NOT NULL DEFAULT 0,
                failure_count                  INTEGER NOT NULL DEFAULT 0,
                consecutive_failures           INTEGER NOT NULL DEFAULT 0,
                connection_success_rate        REAL NOT NULL DEFAULT 0.0,
                latest_establish_ms            INTEGER NOT NULL DEFAULT 0,
                latest_latency_ms              INTEGER NOT NULL DEFAULT 0,
                ewma_latency_ms                REAL NOT NULL DEFAULT 0.0,
                latest_jitter_ms               REAL NOT NULL DEFAULT 0.0,
                ewma_jitter_ms                 REAL NOT NULL DEFAULT 0.0,
                latest_packet_loss_pct         REAL NOT NULL DEFAULT 0.0,
                ewma_packet_loss_pct           REAL NOT NULL DEFAULT 0.0,
                latest_throughput_kbps         REAL NOT NULL DEFAULT 0.0,
                best_throughput_kbps           REAL NOT NULL DEFAULT 0.0,
                stability_score                REAL NOT NULL DEFAULT 0.0,
                personalized_score             REAL NOT NULL DEFAULT 0.0,
                PRIMARY KEY (server_id, network_profile)
            );
            """.trimIndent()
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_net_stats_profile_score ON network_server_stats(network_profile, personalized_score DESC);"
        )

        // 3) Current materialized Personalized Top 50 + Qualified Backup Pool per Network Profile
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS local_network_rankings (
                network_profile     TEXT NOT NULL,
                server_id           TEXT NOT NULL,
                config_fingerprint  TEXT NOT NULL DEFAULT '',
                pool_tier           TEXT NOT NULL,
                rank_position       INTEGER NOT NULL,
                personalized_score  REAL NOT NULL DEFAULT 0.0,
                stability_score     REAL NOT NULL DEFAULT 0.0,
                updated_at_ms       INTEGER NOT NULL,
                PRIMARY KEY (network_profile, server_id)
            );
            """.trimIndent()
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_local_rank_profile_pos ON local_network_rankings(network_profile, rank_position ASC);"
        )

        // 4) Append-only local ranking history (never overwrites prior ranking snapshots)
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS local_ranking_history (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_batch_id       TEXT NOT NULL,
                ranked_at_ms        INTEGER NOT NULL,
                network_profile     TEXT NOT NULL,
                scan_mode           TEXT NOT NULL,
                server_id           TEXT NOT NULL,
                pool_tier           TEXT NOT NULL,
                rank_position       INTEGER NOT NULL,
                personalized_score  REAL NOT NULL DEFAULT 0.0,
                stability_score     REAL NOT NULL DEFAULT 0.0
            );
            """.trimIndent()
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_rank_hist_net_time ON local_ranking_history(network_profile, ranked_at_ms DESC);"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_rank_hist_srv ON local_ranking_history(server_id, network_profile, ranked_at_ms DESC);"
        )
    }

    private fun upgradeToV4(db: SQLiteDatabase) {
        // 5) Privacy-minimal opt-in Community Testing reports (zero credentials, zero raw URIs, zero PII/GPS)
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS community_test_reports (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id           TEXT NOT NULL UNIQUE,
                server_id           TEXT NOT NULL,
                config_fingerprint  TEXT NOT NULL,
                protocol            TEXT NOT NULL,
                tested_at_ms        INTEGER NOT NULL,
                success             INTEGER NOT NULL DEFAULT 0,
                handshake_ms        INTEGER NOT NULL DEFAULT 0,
                latency_ms          INTEGER NOT NULL DEFAULT 0,
                download_kbps       REAL NOT NULL DEFAULT 0.0,
                stability_score     REAL NOT NULL DEFAULT 0.0,
                dns_ok              INTEGER NOT NULL DEFAULT 0,
                tcp_ok              INTEGER NOT NULL DEFAULT 0,
                udp_ok              INTEGER NOT NULL DEFAULT 0,
                failure_reason      TEXT NOT NULL DEFAULT '',
                verified_country    TEXT NOT NULL DEFAULT '',
                country_confidence  TEXT NOT NULL DEFAULT 'UNVERIFIED',
                vpn_interference    INTEGER NOT NULL DEFAULT 0,
                network_transport   TEXT NOT NULL DEFAULT 'UNKNOWN',
                submitted           INTEGER NOT NULL DEFAULT 0,
                submitted_at_ms     INTEGER NOT NULL DEFAULT 0
            );
            """.trimIndent()
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_comm_rep_pending ON community_test_reports(submitted, tested_at_ms ASC);"
        )
        db.execSQL(
            "CREATE INDEX IF NOT EXISTS idx_comm_rep_recent ON community_test_reports(tested_at_ms DESC);"
        )
    }

    /** ترحيل المفضلة القديمة المخزنة في SharedPreferences إلى جدول SQLite المستقر لمرة واحدة. */
    fun migrateLegacyFavoritesIfNeeded(prefs: Prefs) {
        if (prefs.favoritesMigratedV33) return
        synchronized(lock) {
            if (prefs.favoritesMigratedV33) return
            val legacySet = prefs.favorites
            val now = System.currentTimeMillis()
            if (legacySet.isNotEmpty()) {
                val db = writableDatabase
                db.beginTransaction()
                try {
                    legacySet.forEachIndexed { idx, rawCfg ->
                        val sid = Converters.stableServerId(rawCfg)
                        if (sid.isNotBlank()) {
                            val cv = ContentValues().apply {
                                put("server_id", sid)
                                put("custom_name", "")
                                put("default_label", Converters.extractRemark(rawCfg).ifBlank { "bahrain-vpn #${idx + 1}" })
                                put("group_name", "عام")
                                put("protocol", Converters.protocolBadge(rawCfg))
                                put("masked_endpoint", Converters.maskedEndpointLabel(rawCfg))
                                put("country", "")
                                put("sort_order", idx)
                                put("added_at_ms", now)
                                put("updated_at_ms", now)
                            }
                            db.insertWithOnConflict("favorite_servers", null, cv, SQLiteDatabase.CONFLICT_IGNORE)
                        }
                    }
                    db.setTransactionSuccessful()
                } finally {
                    db.endTransaction()
                }
            }
            prefs.favoritesMigratedV33 = true
        }
    }

    // ─────────────────────────── 1) Favorites API ───────────────────────────

    fun upsertFavorite(
        cfgOrServerId: String,
        defaultLabel: String = "",
        customName: String? = null,
        groupName: String? = null,
        protocol: String = "",
        maskedEndpoint: String = "",
        country: String = "",
    ): FavoriteServerRecord? = synchronized(lock) {
        val sid = if (cfgOrServerId.contains("://")) Converters.stableServerId(cfgOrServerId) else cfgOrServerId.trim()
        if (sid.isBlank()) return null
        val now = System.currentTimeMillis()
        val existing = getFavorite(sid)
        val db = writableDatabase
        val cv = ContentValues().apply {
            put("server_id", sid)
            put("custom_name", (customName ?: existing?.customName ?: "").trim().take(64))
            put("default_label", defaultLabel.ifBlank { existing?.defaultLabel ?: "" }.take(80))
            put("group_name", (groupName ?: existing?.groupName ?: "عام").trim().ifBlank { "عام" }.take(32))
            put("protocol", protocol.ifBlank { existing?.protocol ?: (if (cfgOrServerId.contains("://")) Converters.protocolBadge(cfgOrServerId) else "") })
            put("masked_endpoint", maskedEndpoint.ifBlank { existing?.maskedEndpoint ?: (if (cfgOrServerId.contains("://")) Converters.maskedEndpointLabel(cfgOrServerId) else "") })
            put("country", country.ifBlank { existing?.country ?: "" }.uppercase())
            put("sort_order", existing?.sortOrder ?: 0)
            put("added_at_ms", existing?.addedAtMs ?: now)
            put("updated_at_ms", now)
        }
        db.insertWithOnConflict("favorite_servers", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
        getFavorite(sid)
    }

    fun removeFavorite(cfgOrServerId: String): Boolean = synchronized(lock) {
        val sid = if (cfgOrServerId.contains("://")) Converters.stableServerId(cfgOrServerId) else cfgOrServerId.trim()
        if (sid.isBlank()) return false
        writableDatabase.delete("favorite_servers", "server_id = ?", arrayOf(sid)) > 0
    }

    fun isFavorite(cfgOrServerId: String): Boolean = getFavorite(cfgOrServerId) != null

    fun getFavorite(cfgOrServerId: String): FavoriteServerRecord? = synchronized(lock) {
        val sid = if (cfgOrServerId.contains("://")) Converters.stableServerId(cfgOrServerId) else cfgOrServerId.trim()
        if (sid.isBlank()) return null
        readableDatabase.rawQuery(
            "SELECT * FROM favorite_servers WHERE server_id = ? LIMIT 1",
            arrayOf(sid),
        ).use { c ->
            if (!c.moveToFirst()) return null
            FavoriteServerRecord(
                serverId = c.getString(c.getColumnIndexOrThrow("server_id")),
                customName = c.getString(c.getColumnIndexOrThrow("custom_name")),
                defaultLabel = c.getString(c.getColumnIndexOrThrow("default_label")),
                groupName = c.getString(c.getColumnIndexOrThrow("group_name")),
                protocol = c.getString(c.getColumnIndexOrThrow("protocol")),
                maskedEndpoint = c.getString(c.getColumnIndexOrThrow("masked_endpoint")),
                country = c.getString(c.getColumnIndexOrThrow("country")),
                sortOrder = c.getInt(c.getColumnIndexOrThrow("sort_order")),
                addedAtMs = c.getLong(c.getColumnIndexOrThrow("added_at_ms")),
                updatedAtMs = c.getLong(c.getColumnIndexOrThrow("updated_at_ms")),
            )
        }
    }

    fun listFavorites(groupFilter: String = "ALL", sort: FavoriteSortOrder = FavoriteSortOrder.RECENT): List<FavoriteServerRecord> =
        synchronized(lock) {
            val where = if (groupFilter.isNotBlank() && groupFilter != "ALL") "WHERE f.group_name = ?" else ""
            val args = if (where.isNotEmpty()) arrayOf(groupFilter) else emptyArray()
            val orderSql = when (sort) {
                FavoriteSortOrder.RECENT -> "f.added_at_ms DESC"
                FavoriteSortOrder.NAME -> "CASE WHEN f.custom_name != '' THEN f.custom_name ELSE f.default_label END COLLATE NOCASE ASC"
                FavoriteSortOrder.GROUP -> "f.group_name COLLATE NOCASE ASC, f.sort_order ASC, f.added_at_ms DESC"
                FavoriteSortOrder.PERFORMANCE -> "COALESCE(t.best_download_kbps, 0) DESC, CASE WHEN COALESCE(t.ewma_latency_ms, 0) > 0 THEN t.ewma_latency_ms ELSE 99999 END ASC"
            }
            val sql = """
                SELECT f.* FROM favorite_servers f
                LEFT JOIN local_server_telemetry t ON t.server_id = f.server_id
                $where
                ORDER BY $orderSql
            """.trimIndent()
            readableDatabase.rawQuery(sql, args).use { c ->
                buildList {
                    while (c.moveToNext()) {
                        add(
                            FavoriteServerRecord(
                                serverId = c.getString(c.getColumnIndexOrThrow("server_id")),
                                customName = c.getString(c.getColumnIndexOrThrow("custom_name")),
                                defaultLabel = c.getString(c.getColumnIndexOrThrow("default_label")),
                                groupName = c.getString(c.getColumnIndexOrThrow("group_name")),
                                protocol = c.getString(c.getColumnIndexOrThrow("protocol")),
                                maskedEndpoint = c.getString(c.getColumnIndexOrThrow("masked_endpoint")),
                                country = c.getString(c.getColumnIndexOrThrow("country")),
                                sortOrder = c.getInt(c.getColumnIndexOrThrow("sort_order")),
                                addedAtMs = c.getLong(c.getColumnIndexOrThrow("added_at_ms")),
                                updatedAtMs = c.getLong(c.getColumnIndexOrThrow("updated_at_ms")),
                            )
                        )
                    }
                }
            }
        }

    fun favoriteServerIds(): Set<String> = synchronized(lock) {
        readableDatabase.rawQuery("SELECT server_id FROM favorite_servers", emptyArray()).use { c ->
            val out = HashSet<String>()
            while (c.moveToNext()) out.add(c.getString(0))
            out
        }
    }

    fun listFavoriteGroups(): List<String> = synchronized(lock) {
        val base = linkedSetOf("عام", "العمل", "الألعاب", "البث")
        readableDatabase.rawQuery("SELECT DISTINCT group_name FROM favorite_servers ORDER BY group_name ASC", emptyArray()).use { c ->
            while (c.moveToNext()) {
                val g = c.getString(0)?.trim().orEmpty()
                if (g.isNotEmpty()) base.add(g)
            }
        }
        base.toList()
    }

    // ─────────────────────────── 2) Session History API ───────────────────────────

    fun startSessionRecord(
        cfg: String,
        serverLabel: String,
        country: String,
        initialLatencyMs: Long,
        networkType: String,
        nowMs: Long = System.currentTimeMillis(),
    ): Long = synchronized(lock) {
        val sid = Converters.stableServerId(cfg).ifBlank { "unknown" }
        val cv = ContentValues().apply {
            put("server_id", sid)
            put("server_label", serverLabel.take(80))
            put("masked_endpoint", Converters.maskedEndpointLabel(cfg))
            put("protocol", Converters.protocolBadge(cfg))
            put("country", country.uppercase().take(4))
            put("connected_at_ms", nowMs)
            put("disconnected_at_ms", 0L)
            put("duration_sec", 0L)
            put("success", 1)
            put("avg_latency_ms", initialLatencyMs.coerceAtLeast(0L))
            put("network_type", networkType.ifBlank { "UNKNOWN" })
        }
        writableDatabase.insert("connection_history", null, cv)
    }

    fun completeSessionRecord(
        rowId: Long,
        disconnectedAtMs: Long = System.currentTimeMillis(),
        avgLatencyMs: Long = 0L,
        jitterMs: Double = 0.0,
        packetLossPct: Double = 0.0,
        peakDownloadBps: Long = 0L,
        peakUploadBps: Long = 0L,
        totalDownBytes: Long = 0L,
        totalUpBytes: Long = 0L,
        country: String = "",
        failureReason: String = "",
    ) {
        if (rowId <= 0L) return
        synchronized(lock) {
            val db = writableDatabase
            val startMs = db.rawQuery(
                "SELECT connected_at_ms FROM connection_history WHERE id = ?",
                arrayOf(rowId.toString()),
            ).use { c -> if (c.moveToFirst()) c.getLong(0) else disconnectedAtMs }

            val durSec = ((disconnectedAtMs - startMs) / 1000L).coerceAtLeast(0L)
            val cv = ContentValues().apply {
                put("disconnected_at_ms", disconnectedAtMs)
                put("duration_sec", durSec)
                if (avgLatencyMs > 0L) put("avg_latency_ms", avgLatencyMs)
                if (!jitterMs.isNaN() && jitterMs >= 0.0) put("jitter_ms", jitterMs)
                if (!packetLossPct.isNaN() && packetLossPct >= 0.0) put("packet_loss_pct", packetLossPct)
                put("peak_download_bps", peakDownloadBps.coerceAtLeast(0L))
                put("peak_upload_bps", peakUploadBps.coerceAtLeast(0L))
                put("total_down_bytes", totalDownBytes.coerceAtLeast(0L))
                put("total_up_bytes", totalUpBytes.coerceAtLeast(0L))
                if (country.isNotBlank()) put("country", country.uppercase().take(4))
                if (failureReason.isNotBlank()) put("failure_reason", failureReason.take(80))
            }
            db.update("connection_history", cv, "id = ?", arrayOf(rowId.toString()))
        }
    }

    fun recordFailedConnectionAttempt(
        cfg: String,
        serverLabel: String,
        failureReason: String,
        networkType: String,
        nowMs: Long = System.currentTimeMillis(),
    ): Long = synchronized(lock) {
        val sid = Converters.stableServerId(cfg).ifBlank { "unknown" }
        val cv = ContentValues().apply {
            put("server_id", sid)
            put("server_label", serverLabel.take(80))
            put("masked_endpoint", Converters.maskedEndpointLabel(cfg))
            put("protocol", Converters.protocolBadge(cfg))
            put("connected_at_ms", nowMs)
            put("disconnected_at_ms", nowMs)
            put("duration_sec", 0L)
            put("success", 0)
            put("failure_reason", failureReason.take(80))
            put("network_type", networkType.ifBlank { "UNKNOWN" })
        }
        writableDatabase.insert("connection_history", null, cv)
    }

    fun querySessionHistory(
        serverQuery: String = "",
        sinceMs: Long = 0L,
        untilMs: Long = Long.MAX_VALUE,
        sort: HistorySortOrder = HistorySortOrder.RECENT,
        limit: Int = 30,
        offset: Int = 0,
    ): List<ServerSessionRecord> = synchronized(lock) {
        val clauses = ArrayList<String>()
        val args = ArrayList<String>()
        clauses.add("connected_at_ms >= ? AND connected_at_ms <= ?")
        args.add(sinceMs.toString())
        args.add(untilMs.toString())

        val q = serverQuery.trim()
        if (q.isNotEmpty()) {
            clauses.add("(server_label LIKE ? OR masked_endpoint LIKE ? OR protocol LIKE ? OR country LIKE ? OR server_id LIKE ?)")
            val pat = "%$q%"
            repeat(5) { args.add(pat) }
        }

        val orderSql = when (sort) {
            HistorySortOrder.RECENT -> "connected_at_ms DESC, id DESC"
            HistorySortOrder.BEST_PERFORMANCE -> "peak_download_bps DESC, CASE WHEN avg_latency_ms > 0 THEN avg_latency_ms ELSE 99999 END ASC"
            HistorySortOrder.LOWEST_LATENCY -> "CASE WHEN avg_latency_ms > 0 THEN avg_latency_ms ELSE 999999 END ASC, connected_at_ms DESC"
            HistorySortOrder.LONGEST_DURATION -> "duration_sec DESC, connected_at_ms DESC"
        }

        val sql = """
            SELECT * FROM connection_history
            WHERE ${clauses.joinToString(" AND ")}
            ORDER BY $orderSql
            LIMIT ? OFFSET ?
        """.trimIndent()
        args.add(limit.coerceIn(1, 200).toString())
        args.add(offset.coerceAtLeast(0).toString())

        readableDatabase.rawQuery(sql, args.toTypedArray()).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(
                        ServerSessionRecord(
                            id = c.getLong(c.getColumnIndexOrThrow("id")),
                            serverId = c.getString(c.getColumnIndexOrThrow("server_id")),
                            serverLabel = c.getString(c.getColumnIndexOrThrow("server_label")),
                            maskedEndpoint = c.getString(c.getColumnIndexOrThrow("masked_endpoint")),
                            protocol = c.getString(c.getColumnIndexOrThrow("protocol")),
                            country = c.getString(c.getColumnIndexOrThrow("country")),
                            connectedAtMs = c.getLong(c.getColumnIndexOrThrow("connected_at_ms")),
                            disconnectedAtMs = c.getLong(c.getColumnIndexOrThrow("disconnected_at_ms")),
                            durationSec = c.getLong(c.getColumnIndexOrThrow("duration_sec")),
                            success = c.getInt(c.getColumnIndexOrThrow("success")) == 1,
                            avgLatencyMs = c.getLong(c.getColumnIndexOrThrow("avg_latency_ms")),
                            jitterMs = c.getDouble(c.getColumnIndexOrThrow("jitter_ms")),
                            packetLossPct = c.getDouble(c.getColumnIndexOrThrow("packet_loss_pct")),
                            peakDownloadBps = c.getLong(c.getColumnIndexOrThrow("peak_download_bps")),
                            peakUploadBps = c.getLong(c.getColumnIndexOrThrow("peak_upload_bps")),
                            totalDownBytes = c.getLong(c.getColumnIndexOrThrow("total_down_bytes")),
                            totalUpBytes = c.getLong(c.getColumnIndexOrThrow("total_up_bytes")),
                            failureReason = c.getString(c.getColumnIndexOrThrow("failure_reason")),
                            networkType = c.getString(c.getColumnIndexOrThrow("network_type")),
                        )
                    )
                }
            }
        }
    }

    fun countSessionHistory(serverQuery: String = "", sinceMs: Long = 0L): Int = synchronized(lock) {
        val clauses = mutableListOf("connected_at_ms >= ?")
        val args = mutableListOf(sinceMs.toString())
        val q = serverQuery.trim()
        if (q.isNotEmpty()) {
            clauses.add("(server_label LIKE ? OR masked_endpoint LIKE ? OR protocol LIKE ? OR country LIKE ? OR server_id LIKE ?)")
            val pat = "%$q%"
            repeat(5) { args.add(pat) }
        }
        readableDatabase.rawQuery(
            "SELECT COUNT(*) FROM connection_history WHERE ${clauses.joinToString(" AND ")}",
            args.toTypedArray(),
        ).use { c -> if (c.moveToFirst()) c.getInt(0) else 0 }
    }

    fun deleteHistoryEntry(id: Long): Boolean = synchronized(lock) {
        writableDatabase.delete("connection_history", "id = ?", arrayOf(id.toString())) > 0
    }

    fun clearAllHistory() {
        synchronized(lock) {
            writableDatabase.delete("connection_history", null, null)
        }
    }

    fun pruneExpiredHistory(retentionDays: Int, nowMs: Long = System.currentTimeMillis()): Int = synchronized(lock) {
        val cutoff = nowMs - (retentionDays.coerceIn(1, 365).toLong() * 86_400_000L)
        writableDatabase.delete("connection_history", "connected_at_ms < ?", arrayOf(cutoff.toString()))
    }

    // ─────────────────────────── 3) Local Server Telemetry API ───────────────────────────

    fun recordServerProbeOrSessionOutcome(
        cfgOrServerId: String,
        ok: Boolean,
        establishMs: Long = 0L,
        latencyMs: Long = 0L,
        jitterMs: Double = 0.0,
        packetLossPct: Double = 0.0,
        downloadKbps: Double = 0.0,
        uploadKbps: Double = 0.0,
        failureCategory: String = "",
        networkType: String = "",
        nowMs: Long = System.currentTimeMillis(),
    ) {
        val sid = if (cfgOrServerId.contains("://")) Converters.stableServerId(cfgOrServerId) else cfgOrServerId.trim()
        if (sid.isBlank()) return
        synchronized(lock) {
            val prev = getServerTelemetry(sid) ?: LocalServerTelemetry(serverId = sid)
            val alpha = 0.35

            val newAttempts = prev.attempts + 1
            val newSuccesses = prev.successes + (if (ok) 1 else 0)
            val newConsecFail = if (ok) 0 else (prev.consecutiveFailures + 1)

            val newEwmaLat = when {
                !ok || latencyMs <= 0L -> prev.ewmaLatencyMs
                prev.ewmaLatencyMs <= 0.0 -> latencyMs.toDouble()
                else -> alpha * latencyMs.toDouble() + (1.0 - alpha) * prev.ewmaLatencyMs
            }
            val newVariance = when {
                !ok || latencyMs <= 0L -> prev.latencyVarianceMs2
                prev.ewmaLatencyMs <= 0.0 -> 0.0
                else -> {
                    val diff = latencyMs.toDouble() - prev.ewmaLatencyMs
                    (1.0 - alpha) * (prev.latencyVarianceMs2 + alpha * diff * diff)
                }
            }
            val newJitter = when {
                !ok -> prev.ewmaJitterMs
                jitterMs > 0.0 -> if (prev.ewmaJitterMs <= 0.0) jitterMs else (alpha * jitterMs + (1.0 - alpha) * prev.ewmaJitterMs)
                prev.ewmaLatencyMs > 0.0 && latencyMs > 0L -> abs(latencyMs.toDouble() - prev.ewmaLatencyMs)
                else -> prev.ewmaJitterMs
            }
            val sampleLoss = if (ok) packetLossPct.coerceIn(0.0, 100.0) else 100.0
            val newLoss = if (prev.attempts == 0) sampleLoss else (alpha * sampleLoss + (1.0 - alpha) * prev.ewmaPacketLossPct)
            val newEstab = when {
                !ok || establishMs <= 0L -> prev.avgEstablishMs
                prev.avgEstablishMs <= 0L -> establishMs
                else -> (0.4 * establishMs + 0.6 * prev.avgEstablishMs).toLong()
            }
            val trendDelta = if (ok && prev.ewmaLatencyMs > 0.0 && latencyMs > 0L) {
                (prev.ewmaLatencyMs - latencyMs.toDouble()).coerceIn(-250.0, 250.0)
            } else if (!ok) {
                -40.0
            } else {
                prev.recentTrendDelta
            }

            val isWifi = networkType.equals("WIFI", ignoreCase = true)
            val isCell = networkType.equals("CELLULAR", ignoreCase = true)

            val cv = ContentValues().apply {
                put("server_id", sid)
                put("attempts", newAttempts)
                put("successes", newSuccesses)
                put("consecutive_failures", newConsecFail)
                put("last_failure_at_ms", if (!ok) nowMs else prev.lastFailureAtMs)
                put("last_failure_category", if (!ok) failureCategory.take(48) else prev.lastFailureCategory)
                put("last_success_at_ms", if (ok) nowMs else prev.lastSuccessAtMs)
                put("avg_establish_ms", newEstab)
                put("ewma_latency_ms", newEwmaLat)
                put("latency_variance_ms2", newVariance)
                put("ewma_jitter_ms", newJitter)
                put("ewma_packet_loss_pct", newLoss)
                put("best_download_kbps", max(prev.bestDownloadKbps, downloadKbps.coerceAtLeast(0.0)))
                put("best_upload_kbps", max(prev.bestUploadKbps, uploadKbps.coerceAtLeast(0.0)))
                put("wifi_successes", prev.wifiSuccesses + (if (ok && isWifi) 1 else 0))
                put("cellular_successes", prev.cellularSuccesses + (if (ok && isCell) 1 else 0))
                put("recent_trend_delta", trendDelta)
            }
            writableDatabase.insertWithOnConflict("local_server_telemetry", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
        }
    }

    fun getServerTelemetry(cfgOrServerId: String): LocalServerTelemetry? = synchronized(lock) {
        val sid = if (cfgOrServerId.contains("://")) Converters.stableServerId(cfgOrServerId) else cfgOrServerId.trim()
        if (sid.isBlank()) return null
        readableDatabase.rawQuery(
            "SELECT * FROM local_server_telemetry WHERE server_id = ? LIMIT 1",
            arrayOf(sid),
        ).use { c ->
            if (!c.moveToFirst()) return null
            readTelemetryRow(c)
        }
    }

    fun getAllServerTelemetryMap(): Map<String, LocalServerTelemetry> = synchronized(lock) {
        readableDatabase.rawQuery("SELECT * FROM local_server_telemetry", emptyArray()).use { c ->
            val out = HashMap<String, LocalServerTelemetry>()
            while (c.moveToNext()) {
                val row = readTelemetryRow(c)
                out[row.serverId] = row
            }
            out
        }
    }

    private fun readTelemetryRow(c: android.database.Cursor): LocalServerTelemetry =
        LocalServerTelemetry(
            serverId = c.getString(c.getColumnIndexOrThrow("server_id")),
            attempts = c.getInt(c.getColumnIndexOrThrow("attempts")),
            successes = c.getInt(c.getColumnIndexOrThrow("successes")),
            consecutiveFailures = c.getInt(c.getColumnIndexOrThrow("consecutive_failures")),
            lastFailureAtMs = c.getLong(c.getColumnIndexOrThrow("last_failure_at_ms")),
            lastFailureCategory = c.getString(c.getColumnIndexOrThrow("last_failure_category")),
            lastSuccessAtMs = c.getLong(c.getColumnIndexOrThrow("last_success_at_ms")),
            avgEstablishMs = c.getLong(c.getColumnIndexOrThrow("avg_establish_ms")),
            ewmaLatencyMs = c.getDouble(c.getColumnIndexOrThrow("ewma_latency_ms")),
            latencyVarianceMs2 = c.getDouble(c.getColumnIndexOrThrow("latency_variance_ms2")),
            ewmaJitterMs = c.getDouble(c.getColumnIndexOrThrow("ewma_jitter_ms")),
            ewmaPacketLossPct = c.getDouble(c.getColumnIndexOrThrow("ewma_packet_loss_pct")),
            bestDownloadKbps = c.getDouble(c.getColumnIndexOrThrow("best_download_kbps")),
            bestUploadKbps = c.getDouble(c.getColumnIndexOrThrow("best_upload_kbps")),
            wifiSuccesses = c.getInt(c.getColumnIndexOrThrow("wifi_successes")),
            cellularSuccesses = c.getInt(c.getColumnIndexOrThrow("cellular_successes")),
            recentTrendDelta = c.getDouble(c.getColumnIndexOrThrow("recent_trend_delta")),
        )

    // ─────────────────────────── 4) Protection & Timeline Events API ───────────────────────────

    fun recordProtectionEvent(
        category: String,
        titleAr: String,
        detailAr: String = "",
        nowMs: Long = System.currentTimeMillis(),
    ) {
        synchronized(lock) {
            val db = writableDatabase
            val cv = ContentValues().apply {
                put("event_at_ms", nowMs)
                put("category", category.take(32))
                put("title_ar", titleAr.take(120))
                put("detail_ar", detailAr.take(240))
            }
            db.insert("protection_events", null, cv)
            // Keep last 200 events bounded for database compactness
            db.execSQL(
                "DELETE FROM protection_events WHERE id NOT IN (SELECT id FROM protection_events ORDER BY event_at_ms DESC LIMIT 200)"
            )
        }
    }

    fun recentProtectionEvents(limit: Int = 25): List<ProtectionEventRecord> = synchronized(lock) {
        readableDatabase.rawQuery(
            "SELECT * FROM protection_events ORDER BY event_at_ms DESC, id DESC LIMIT ?",
            arrayOf(limit.coerceIn(1, 100).toString()),
        ).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(
                        ProtectionEventRecord(
                            id = c.getLong(c.getColumnIndexOrThrow("id")),
                            eventAtMs = c.getLong(c.getColumnIndexOrThrow("event_at_ms")),
                            category = c.getString(c.getColumnIndexOrThrow("category")),
                            titleAr = c.getString(c.getColumnIndexOrThrow("title_ar")),
                            detailAr = c.getString(c.getColumnIndexOrThrow("detail_ar")),
                        )
                    )
                }
            }
        }
    }

    // ─────────────── 5) Personalized Network Intelligence & Append-Only Scan History (v1) ───────────────

    /**
     * يضيف قراءة فحص جديدة دون استبدال القراءات التاريخية السابقة (Append-Only)،
     * ويحدّث إحصائيات السيرفر المخصّصة لنوع الشبكة الحالي فقط (WIFI أو MOBILE_DATA).
     */
    fun recordNetworkScanMeasurement(
        cfgOrServerId: String,
        configFingerprint: String = "",
        networkProfile: ScanNetworkProfile,
        scanMode: String,
        success: Boolean,
        establishMs: Long = 0L,
        latencyMs: Long = 0L,
        jitterMs: Double = 0.0,
        packetLossPct: Double = 0.0,
        throughputKbps: Double = 0.0,
        stabilityScore: Double = 0.0,
        personalizedScore: Double = 0.0,
        failureReason: String = "",
        nowMs: Long = System.currentTimeMillis(),
    ): NetworkServerProfileStats? = synchronized(lock) {
        val sid = if (cfgOrServerId.contains("://")) Converters.stableServerId(cfgOrServerId) else cfgOrServerId.trim()
        if (sid.isBlank()) return null
        val fp = configFingerprint.ifBlank {
            if (cfgOrServerId.contains("://")) Converters.configFingerprint(cfgOrServerId) else sid
        }.take(64)

        val db = writableDatabase
        db.beginTransaction()
        try {
            // 1. Append-only historical measurement row (never overwrites prior rows)
            val mCv = ContentValues().apply {
                put("server_id", sid)
                put("config_fingerprint", fp)
                put("network_profile", networkProfile.code)
                put("scan_mode", scanMode.take(24))
                put("scanned_at_ms", nowMs)
                put("success", if (success) 1 else 0)
                put("establish_ms", establishMs.coerceAtLeast(0L))
                put("latency_ms", latencyMs.coerceAtLeast(0L))
                put("jitter_ms", jitterMs.coerceAtLeast(0.0))
                put("packet_loss_pct", packetLossPct.coerceIn(0.0, 100.0))
                put("throughput_kbps", throughputKbps.coerceAtLeast(0.0))
                put("stability_score", stabilityScore.coerceIn(0.0, 100.0))
                put("personalized_score", personalizedScore.coerceIn(0.0, 100.0))
                put("failure_reason", failureReason.take(64))
            }
            db.insert("server_scan_measurements", null, mCv)

            // Keep bounded per-(server, network) tail of 120 historical observations to prevent unbounded disk bloat
            db.execSQL(
                """
                DELETE FROM server_scan_measurements
                WHERE server_id = ? AND network_profile = ?
                  AND id NOT IN (
                      SELECT id FROM server_scan_measurements
                      WHERE server_id = ? AND network_profile = ?
                      ORDER BY scanned_at_ms DESC, id DESC LIMIT 120
                  )
                """.trimIndent(),
                arrayOf(sid, networkProfile.code, sid, networkProfile.code),
            )

            // 2. Roll up per-network-profile stats (WIFI and MOBILE_DATA strictly isolated)
            val prev = readSingleNetworkStatLocked(db, sid, networkProfile)
            // If config_fingerprint changed upstream, preserve history rows while resetting stale EWMA bias
            val fpChanged = prev != null && prev.configFingerprint.isNotBlank() && prev.configFingerprint != fp
            val baseScans = (prev?.scanCount ?: 0) + 1
            val baseSucc = (prev?.successCount ?: 0) + (if (success) 1 else 0)
            val baseFail = (prev?.failureCount ?: 0) + (if (success) 0 else 1)
            val consecFail = if (success) 0 else ((prev?.consecutiveFailures ?: 0) + 1)
            val succRate = baseSucc.toDouble() / max(1, baseScans).toDouble()
            val alpha = 0.35

            val nextEwmaLat = when {
                success && latencyMs > 0L && (prev == null || prev.ewmaLatencyMs <= 0.0 || fpChanged) -> latencyMs.toDouble()
                success && latencyMs > 0L && prev != null -> alpha * latencyMs.toDouble() + (1.0 - alpha) * prev.ewmaLatencyMs
                else -> prev?.ewmaLatencyMs ?: 0.0
            }
            val nextEwmaJit = when {
                success && (prev == null || fpChanged) -> jitterMs.coerceAtLeast(0.0)
                success && prev != null -> alpha * jitterMs.coerceAtLeast(0.0) + (1.0 - alpha) * prev.ewmaJitterMs
                else -> prev?.ewmaJitterMs ?: 0.0
            }
            val effLoss = if (success) packetLossPct.coerceIn(0.0, 100.0) else 100.0
            val nextEwmaLoss = if (prev == null || fpChanged) {
                effLoss
            } else {
                alpha * effLoss + (1.0 - alpha) * prev.ewmaPacketLossPct
            }
            val nextLatestTp = when {
                success && throughputKbps > 0.0 -> throughputKbps
                fpChanged -> 0.0
                else -> prev?.latestThroughputKbps ?: 0.0
            }
            val nextBestTp = if (fpChanged) {
                if (success) throughputKbps.coerceAtLeast(0.0) else 0.0
            } else {
                max(prev?.bestThroughputKbps ?: 0.0, if (success) throughputKbps else 0.0)
            }

            val computedStab = if (stabilityScore > 0.0) {
                stabilityScore
            } else {
                val srPart = succRate * 48.0
                val lossPart = ((100.0 - nextEwmaLoss).coerceIn(0.0, 100.0) / 100.0) * 27.0
                val jitPart = ((1.0 - (nextEwmaJit / 220.0)).coerceIn(0.0, 1.0)) * 15.0
                val sampleBonus = (minOf(baseSucc, 5) / 5.0) * 10.0
                val failPenalty = consecFail * 14.0
                (srPart + lossPart + jitPart + sampleBonus - failPenalty).coerceIn(0.0, 100.0)
            }

            val sCv = ContentValues().apply {
                put("server_id", sid)
                put("network_profile", networkProfile.code)
                put("config_fingerprint", fp)
                put("last_successful_connection_ms", if (success) nowMs else (prev?.lastSuccessfulConnectionMs ?: 0L))
                put("last_scan_at_ms", nowMs)
                put("scan_count", baseScans)
                put("success_count", baseSucc)
                put("failure_count", baseFail)
                put("consecutive_failures", consecFail)
                put("connection_success_rate", succRate)
                put("latest_establish_ms", if (success && establishMs > 0L) establishMs else (prev?.latestEstablishMs ?: 0L))
                put("latest_latency_ms", if (success && latencyMs > 0L) latencyMs else (if (fpChanged) 0L else (prev?.latestLatencyMs ?: 0L)))
                put("ewma_latency_ms", nextEwmaLat)
                put("latest_jitter_ms", if (success) jitterMs.coerceAtLeast(0.0) else (prev?.latestJitterMs ?: 0.0))
                put("ewma_jitter_ms", nextEwmaJit)
                put("latest_packet_loss_pct", effLoss)
                put("ewma_packet_loss_pct", nextEwmaLoss)
                put("latest_throughput_kbps", nextLatestTp)
                put("best_throughput_kbps", nextBestTp)
                put("stability_score", computedStab)
                put("personalized_score", if (personalizedScore > 0.0) personalizedScore else (prev?.personalizedScore ?: 0.0))
            }
            db.insertWithOnConflict("network_server_stats", null, sCv, SQLiteDatabase.CONFLICT_REPLACE)

            val updated = readSingleNetworkStatLocked(db, sid, networkProfile)
            db.setTransactionSuccessful()
            return updated
        } finally {
            db.endTransaction()
        }
    }

    private fun readSingleNetworkStatLocked(
        db: SQLiteDatabase,
        serverId: String,
        profile: ScanNetworkProfile,
    ): NetworkServerProfileStats? =
        db.rawQuery(
            "SELECT * FROM network_server_stats WHERE server_id = ? AND network_profile = ? LIMIT 1",
            arrayOf(serverId, profile.code),
        ).use { c ->
            if (!c.moveToFirst()) null else readNetworkStatRow(c)
        }

    private fun readNetworkStatRow(c: android.database.Cursor): NetworkServerProfileStats =
        NetworkServerProfileStats(
            serverId = c.getString(c.getColumnIndexOrThrow("server_id")),
            networkProfile = ScanNetworkProfile.fromTransportCode(c.getString(c.getColumnIndexOrThrow("network_profile"))),
            configFingerprint = c.getString(c.getColumnIndexOrThrow("config_fingerprint")),
            lastSuccessfulConnectionMs = c.getLong(c.getColumnIndexOrThrow("last_successful_connection_ms")),
            lastScanAtMs = c.getLong(c.getColumnIndexOrThrow("last_scan_at_ms")),
            scanCount = c.getInt(c.getColumnIndexOrThrow("scan_count")),
            successCount = c.getInt(c.getColumnIndexOrThrow("success_count")),
            failureCount = c.getInt(c.getColumnIndexOrThrow("failure_count")),
            consecutiveFailures = c.getInt(c.getColumnIndexOrThrow("consecutive_failures")),
            connectionSuccessRate = c.getDouble(c.getColumnIndexOrThrow("connection_success_rate")),
            latestEstablishMs = c.getLong(c.getColumnIndexOrThrow("latest_establish_ms")),
            latestLatencyMs = c.getLong(c.getColumnIndexOrThrow("latest_latency_ms")),
            ewmaLatencyMs = c.getDouble(c.getColumnIndexOrThrow("ewma_latency_ms")),
            latestJitterMs = c.getDouble(c.getColumnIndexOrThrow("latest_jitter_ms")),
            ewmaJitterMs = c.getDouble(c.getColumnIndexOrThrow("ewma_jitter_ms")),
            latestPacketLossPct = c.getDouble(c.getColumnIndexOrThrow("latest_packet_loss_pct")),
            ewmaPacketLossPct = c.getDouble(c.getColumnIndexOrThrow("ewma_packet_loss_pct")),
            latestThroughputKbps = c.getDouble(c.getColumnIndexOrThrow("latest_throughput_kbps")),
            bestThroughputKbps = c.getDouble(c.getColumnIndexOrThrow("best_throughput_kbps")),
            stabilityScore = c.getDouble(c.getColumnIndexOrThrow("stability_score")),
            personalizedScore = c.getDouble(c.getColumnIndexOrThrow("personalized_score")),
        )

    fun getNetworkStatsMap(profile: ScanNetworkProfile): Map<String, NetworkServerProfileStats> = synchronized(lock) {
        readableDatabase.rawQuery(
            "SELECT * FROM network_server_stats WHERE network_profile = ?",
            arrayOf(profile.code),
        ).use { c ->
            val out = HashMap<String, NetworkServerProfileStats>()
            while (c.moveToNext()) {
                val r = readNetworkStatRow(c)
                out[r.serverId] = r
            }
            out
        }
    }

    fun getServerScanHistory(
        serverId: String,
        profile: ScanNetworkProfile? = null,
        limit: Int = 50,
    ): List<ScanMeasurementSample> = synchronized(lock) {
        val where = if (profile != null) "WHERE server_id = ? AND network_profile = ?" else "WHERE server_id = ?"
        val args = if (profile != null) {
            arrayOf(serverId, profile.code, limit.coerceIn(1, 200).toString())
        } else {
            arrayOf(serverId, limit.coerceIn(1, 200).toString())
        }
        readableDatabase.rawQuery(
            "SELECT * FROM server_scan_measurements $where ORDER BY scanned_at_ms DESC, id DESC LIMIT ?",
            args,
        ).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(
                        ScanMeasurementSample(
                            id = c.getLong(c.getColumnIndexOrThrow("id")),
                            serverId = c.getString(c.getColumnIndexOrThrow("server_id")),
                            configFingerprint = c.getString(c.getColumnIndexOrThrow("config_fingerprint")),
                            networkProfile = ScanNetworkProfile.fromTransportCode(c.getString(c.getColumnIndexOrThrow("network_profile"))),
                            scanMode = c.getString(c.getColumnIndexOrThrow("scan_mode")),
                            scannedAtMs = c.getLong(c.getColumnIndexOrThrow("scanned_at_ms")),
                            success = c.getInt(c.getColumnIndexOrThrow("success")) == 1,
                            establishMs = c.getLong(c.getColumnIndexOrThrow("establish_ms")),
                            latencyMs = c.getLong(c.getColumnIndexOrThrow("latency_ms")),
                            jitterMs = c.getDouble(c.getColumnIndexOrThrow("jitter_ms")),
                            packetLossPct = c.getDouble(c.getColumnIndexOrThrow("packet_loss_pct")),
                            throughputKbps = c.getDouble(c.getColumnIndexOrThrow("throughput_kbps")),
                            stabilityScore = c.getDouble(c.getColumnIndexOrThrow("stability_score")),
                            personalizedScore = c.getDouble(c.getColumnIndexOrThrow("personalized_score")),
                            failureReason = c.getString(c.getColumnIndexOrThrow("failure_reason")),
                        )
                    )
                }
            }
        }
    }

    /**
     * يحفظ الترتيب المحلي المخصّص (Top 50 + الاحتياطي المؤهّل) لشبكة معيّنة (WIFI أو MOBILE_DATA)،
     * ويضيف لقطة تاريخية دائمة في `local_ranking_history` دون الكتابة فوق السجلات السابقة.
     */
    fun savePersonalizedNetworkRankings(
        profile: ScanNetworkProfile,
        scanMode: String,
        entries: List<PersonalizedRankEntry>,
        recordHistorySnapshot: Boolean = true,
        nowMs: Long = System.currentTimeMillis(),
    ) {
        synchronized(lock) {
            val db = writableDatabase
            val batchId = "${profile.code}_${scanMode}_${nowMs}"
            db.beginTransaction()
            try {
                db.delete("local_network_rankings", "network_profile = ?", arrayOf(profile.code))
                for (e in entries) {
                    val cv = ContentValues().apply {
                        put("network_profile", profile.code)
                        put("server_id", e.serverId)
                        put("config_fingerprint", e.configFingerprint)
                        put("pool_tier", e.poolTier.code)
                        put("rank_position", e.rankPosition)
                        put("personalized_score", e.personalizedScore)
                        put("stability_score", e.stabilityScore)
                        put("updated_at_ms", nowMs)
                    }
                    db.insertWithOnConflict("local_network_rankings", null, cv, SQLiteDatabase.CONFLICT_REPLACE)

                    // Sync personalized_score back into network_server_stats for fast indexed lookup
                    val stUpdate = ContentValues().apply {
                        put("personalized_score", e.personalizedScore)
                        put("stability_score", e.stabilityScore)
                    }
                    db.update(
                        "network_server_stats",
                        stUpdate,
                        "server_id = ? AND network_profile = ?",
                        arrayOf(e.serverId, profile.code),
                    )

                    if (recordHistorySnapshot) {
                        val hCv = ContentValues().apply {
                            put("scan_batch_id", batchId)
                            put("ranked_at_ms", nowMs)
                            put("network_profile", profile.code)
                            put("scan_mode", scanMode.take(24))
                            put("server_id", e.serverId)
                            put("pool_tier", e.poolTier.code)
                            put("rank_position", e.rankPosition)
                            put("personalized_score", e.personalizedScore)
                            put("stability_score", e.stabilityScore)
                        }
                        db.insert("local_ranking_history", null, hCv)
                    }
                }
                if (recordHistorySnapshot) {
                    db.execSQL(
                        """
                        DELETE FROM local_ranking_history
                        WHERE network_profile = ?
                          AND id NOT IN (
                              SELECT id FROM local_ranking_history
                              WHERE network_profile = ?
                              ORDER BY ranked_at_ms DESC, id DESC LIMIT 2500
                          )
                        """.trimIndent(),
                        arrayOf(profile.code, profile.code),
                    )
                }
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        }
    }

    fun getPersonalizedRankings(
        profile: ScanNetworkProfile,
        tierFilter: LocalPoolTier? = null,
    ): List<PersonalizedRankEntry> = synchronized(lock) {
        val where = if (tierFilter != null) {
            "WHERE network_profile = ? AND pool_tier = ?"
        } else {
            "WHERE network_profile = ?"
        }
        val args = if (tierFilter != null) arrayOf(profile.code, tierFilter.code) else arrayOf(profile.code)
        readableDatabase.rawQuery(
            "SELECT * FROM local_network_rankings $where ORDER BY rank_position ASC",
            args,
        ).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(
                        PersonalizedRankEntry(
                            networkProfile = ScanNetworkProfile.fromTransportCode(c.getString(c.getColumnIndexOrThrow("network_profile"))),
                            serverId = c.getString(c.getColumnIndexOrThrow("server_id")),
                            configFingerprint = c.getString(c.getColumnIndexOrThrow("config_fingerprint")),
                            poolTier = LocalPoolTier.fromCode(c.getString(c.getColumnIndexOrThrow("pool_tier"))),
                            rankPosition = c.getInt(c.getColumnIndexOrThrow("rank_position")),
                            personalizedScore = c.getDouble(c.getColumnIndexOrThrow("personalized_score")),
                            stabilityScore = c.getDouble(c.getColumnIndexOrThrow("stability_score")),
                            updatedAtMs = c.getLong(c.getColumnIndexOrThrow("updated_at_ms")),
                        )
                    )
                }
            }
        }
    }

    fun getRankingHistoryForServer(
        serverId: String,
        profile: ScanNetworkProfile? = null,
        limit: Int = 30,
    ): List<RankingHistorySnapshotRow> = synchronized(lock) {
        val where = if (profile != null) "WHERE server_id = ? AND network_profile = ?" else "WHERE server_id = ?"
        val args = if (profile != null) {
            arrayOf(serverId, profile.code, limit.coerceIn(1, 100).toString())
        } else {
            arrayOf(serverId, limit.coerceIn(1, 100).toString())
        }
        readableDatabase.rawQuery(
            "SELECT * FROM local_ranking_history $where ORDER BY ranked_at_ms DESC, id DESC LIMIT ?",
            args,
        ).use { c ->
            buildList {
                while (c.moveToNext()) {
                    add(
                        RankingHistorySnapshotRow(
                            id = c.getLong(c.getColumnIndexOrThrow("id")),
                            scanBatchId = c.getString(c.getColumnIndexOrThrow("scan_batch_id")),
                            rankedAtMs = c.getLong(c.getColumnIndexOrThrow("ranked_at_ms")),
                            networkProfile = ScanNetworkProfile.fromTransportCode(c.getString(c.getColumnIndexOrThrow("network_profile"))),
                            scanMode = c.getString(c.getColumnIndexOrThrow("scan_mode")),
                            serverId = c.getString(c.getColumnIndexOrThrow("server_id")),
                            poolTier = LocalPoolTier.fromCode(c.getString(c.getColumnIndexOrThrow("pool_tier"))),
                            rankPosition = c.getInt(c.getColumnIndexOrThrow("rank_position")),
                            personalizedScore = c.getDouble(c.getColumnIndexOrThrow("personalized_score")),
                            stabilityScore = c.getDouble(c.getColumnIndexOrThrow("stability_score")),
                        )
                    )
                }
            }
        }
    }

    // ─────────────────── Community Testing Reports (Opt-In, Secret-Free) ───────────────────

    private fun readCommunityReportRow(c: android.database.Cursor): CommunityTestReportRecord =
        CommunityTestReportRecord(
            id = c.getLong(c.getColumnIndexOrThrow("id")),
            reportId = c.getString(c.getColumnIndexOrThrow("report_id")),
            serverId = c.getString(c.getColumnIndexOrThrow("server_id")),
            configFingerprint = c.getString(c.getColumnIndexOrThrow("config_fingerprint")),
            protocol = c.getString(c.getColumnIndexOrThrow("protocol")),
            testedAtMs = c.getLong(c.getColumnIndexOrThrow("tested_at_ms")),
            success = c.getInt(c.getColumnIndexOrThrow("success")) == 1,
            handshakeMs = c.getLong(c.getColumnIndexOrThrow("handshake_ms")),
            latencyMs = c.getLong(c.getColumnIndexOrThrow("latency_ms")),
            downloadKbps = c.getDouble(c.getColumnIndexOrThrow("download_kbps")),
            stabilityScore = c.getDouble(c.getColumnIndexOrThrow("stability_score")),
            dnsOk = c.getInt(c.getColumnIndexOrThrow("dns_ok")) == 1,
            tcpOk = c.getInt(c.getColumnIndexOrThrow("tcp_ok")) == 1,
            udpOk = c.getInt(c.getColumnIndexOrThrow("udp_ok")) == 1,
            failureReason = c.getString(c.getColumnIndexOrThrow("failure_reason")),
            verifiedCountry = c.getString(c.getColumnIndexOrThrow("verified_country")),
            countryConfidence = c.getString(c.getColumnIndexOrThrow("country_confidence")),
            vpnInterference = c.getInt(c.getColumnIndexOrThrow("vpn_interference")) == 1,
            networkTransport = c.getString(c.getColumnIndexOrThrow("network_transport")),
            submitted = c.getInt(c.getColumnIndexOrThrow("submitted")) == 1,
            submittedAtMs = c.getLong(c.getColumnIndexOrThrow("submitted_at_ms")),
        )

    fun insertCommunityReport(report: CommunityTestReportRecord): Long = synchronized(lock) {
        val safeSid = report.serverId.trim().lowercase().filter { it in '0'..'9' || it in 'a'..'f' }.take(32)
        val safeFp = report.configFingerprint.trim().lowercase().filter { it in '0'..'9' || it in 'a'..'f' }.take(64)
        require(safeSid.isNotEmpty() && safeFp.isNotEmpty()) { "Missing canonical fingerprint" }
        val db = writableDatabase
        val cv = ContentValues().apply {
            put("report_id", report.reportId.take(64))
            put("server_id", safeSid)
            put("config_fingerprint", safeFp)
            put("protocol", report.protocol.trim().lowercase().take(16))
            put("tested_at_ms", report.testedAtMs)
            put("success", if (report.success) 1 else 0)
            put("handshake_ms", report.handshakeMs.coerceAtLeast(0L))
            put("latency_ms", report.latencyMs.coerceAtLeast(0L))
            put("download_kbps", report.downloadKbps.coerceAtLeast(0.0))
            put("stability_score", report.stabilityScore.coerceIn(0.0, 100.0))
            put("dns_ok", if (report.dnsOk) 1 else 0)
            put("tcp_ok", if (report.tcpOk) 1 else 0)
            put("udp_ok", if (report.udpOk) 1 else 0)
            put("failure_reason", report.failureReason.replace("://", "_").take(48))
            put("verified_country", report.verifiedCountry.trim().uppercase().take(4))
            put("country_confidence", report.countryConfidence.trim().uppercase().take(32))
            put("vpn_interference", if (report.vpnInterference) 1 else 0)
            put("network_transport", report.networkTransport.trim().uppercase().take(16))
            put("submitted", if (report.submitted) 1 else 0)
            put("submitted_at_ms", report.submittedAtMs.coerceAtLeast(0L))
        }
        val rowId = db.insertWithOnConflict("community_test_reports", null, cv, SQLiteDatabase.CONFLICT_REPLACE)
        // Bound local table size to most recent 1000 rows
        db.execSQL(
            """
            DELETE FROM community_test_reports
            WHERE id NOT IN (
                SELECT id FROM community_test_reports ORDER BY tested_at_ms DESC, id DESC LIMIT 1000
            )
            """.trimIndent()
        )
        rowId
    }

    fun countCommunityReportsSince(sinceMs: Long): Int = synchronized(lock) {
        readableDatabase.rawQuery(
            "SELECT COUNT(*) FROM community_test_reports WHERE tested_at_ms >= ?",
            arrayOf(sinceMs.toString()),
        ).use { c -> if (c.moveToFirst()) c.getInt(0) else 0 }
    }

    fun listPendingCommunityReports(limit: Int = 25): List<CommunityTestReportRecord> = synchronized(lock) {
        readableDatabase.rawQuery(
            """
            SELECT * FROM community_test_reports
            WHERE submitted = 0 AND vpn_interference = 0 AND country_confidence = 'VERIFIED_DIRECT_IP'
            ORDER BY tested_at_ms ASC LIMIT ?
            """.trimIndent(),
            arrayOf(limit.coerceIn(1, 100).toString()),
        ).use { c ->
            buildList {
                while (c.moveToNext()) add(readCommunityReportRow(c))
            }
        }
    }

    fun listRecentCommunityReports(limit: Int = 40): List<CommunityTestReportRecord> = synchronized(lock) {
        readableDatabase.rawQuery(
            "SELECT * FROM community_test_reports ORDER BY tested_at_ms DESC, id DESC LIMIT ?",
            arrayOf(limit.coerceIn(1, 200).toString()),
        ).use { c ->
            buildList {
                while (c.moveToNext()) add(readCommunityReportRow(c))
            }
        }
    }

    fun markCommunityReportsSubmitted(reportIds: List<String>, nowMs: Long = System.currentTimeMillis()): Int = synchronized(lock) {
        if (reportIds.isEmpty()) return 0
        val db = writableDatabase
        var updated = 0
        db.beginTransaction()
        try {
            for (rid in reportIds) {
                val cv = ContentValues().apply {
                    put("submitted", 1)
                    put("submitted_at_ms", nowMs)
                }
                updated += db.update("community_test_reports", cv, "report_id = ?", arrayOf(rid))
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        updated
    }

    fun getCommunityReportsSummary(): CommunityReportStatsSummary = synchronized(lock) {
        readableDatabase.rawQuery(
            """
            SELECT
                COUNT(*) AS total_cnt,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) AS ok_cnt,
                SUM(CASE WHEN verified_country = 'IR' AND vpn_interference = 0 THEN 1 ELSE 0 END) AS ir_cnt,
                SUM(CASE WHEN submitted = 0 AND vpn_interference = 0 AND country_confidence = 'VERIFIED_DIRECT_IP' THEN 1 ELSE 0 END) AS pend_cnt,
                SUM(CASE WHEN submitted = 1 THEN 1 ELSE 0 END) AS sub_cnt
            FROM community_test_reports
            """.trimIndent(),
            null,
        ).use { c ->
            if (!c.moveToFirst()) CommunityReportStatsSummary()
            else CommunityReportStatsSummary(
                totalTested = c.getInt(0),
                totalSuccess = c.getInt(1),
                verifiedIranCount = c.getInt(2),
                pendingUploadCount = c.getInt(3),
                submittedCount = c.getInt(4),
            )
        }
    }

    fun clearAllCommunityReports() = synchronized(lock) {
        writableDatabase.delete("community_test_reports", null, null)
    }
}
