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
import kotlin.math.abs
import kotlin.math.max

enum class HistorySortOrder(val key: String, val labelAr: String) {
    RECENT("RECENT", "الأحدث"),
    BEST_PERFORMANCE("BEST_PERFORMANCE", "الأعلى سرعة"),
    LOWEST_LATENCY("LOWEST_LATENCY", "الأقل تأخيرًا"),
    LONGEST_DURATION("LONGEST_DURATION", "الأطول مدة");

    companion object {
        fun fromKey(raw: String?): HistorySortOrder =
            entries.firstOrNull { it.key.equals(raw?.trim(), ignoreCase = true) } ?: RECENT
    }
}

enum class FavoriteSortOrder(val key: String, val labelAr: String) {
    RECENT("RECENT", "الأحدث إضافة"),
    NAME("NAME", "الاسم"),
    GROUP("GROUP", "المجموعة"),
    PERFORMANCE("PERFORMANCE", "الأفضل أداءً");

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

class ClientDatabase private constructor(ctx: Context) :
    SQLiteOpenHelper(ctx.applicationContext, DB_NAME, null, DB_VERSION) {

    companion object {
        const val DB_NAME = "bahrain_vpn_client.db"
        const val DB_VERSION = 2

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
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 1) {
            createSchemaV1(db)
        }
        if (oldVersion < 2 && newVersion >= 2) {
            upgradeToV2(db)
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
}
