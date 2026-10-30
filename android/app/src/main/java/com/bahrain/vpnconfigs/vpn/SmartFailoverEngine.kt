// =====================================================================
// SmartFailoverEngine.kt — محرك التبديل التلقائي الذكي السريع (v3.1).
// يرصد سقوط النفق خلال ~ثانيتين عبر فحص تأكيدي مزدوج يمنع التبديل الخاطئ،
// ويختار تلقائيًا ثاني أسرع سيرفر شغّال (مع أولوية عقد VIP والسرعة المقاسة من الهاتف)
// مع عزل مؤقت (Cooldown) للسيرفر الساقط لمنع التذبذب.
// =====================================================================
package com.bahrain.vpnconfigs.vpn

import com.bahrain.vpnconfigs.engine.Converters
import java.util.concurrent.ConcurrentHashMap

object SmartFailoverEngine {

    const val COOLDOWN_WINDOW_MS: Long = 120_000L
    const val HEALTHY_CHECK_INTERVAL_MS: Long = 8_000L
    const val RAPID_CONFIRM_DELAY_MS: Long = 600L
    const val SECONDARY_CONFIRM_URL: String = "https://cp.cloudflare.com/generate_204"

    private val dropTimestampsMs = ConcurrentHashMap<String, Long>()

    fun recordServerDrop(cfg: String, nowMs: Long = System.currentTimeMillis()) {
        val clean = Converters.cleanUri(cfg)
        if (clean.isNotEmpty()) {
            dropTimestampsMs[clean] = nowMs
        }
    }

    fun recordServerHealthy(cfg: String) {
        val clean = Converters.cleanUri(cfg)
        if (clean.isNotEmpty()) {
            dropTimestampsMs.remove(clean)
        }
    }

    fun clearForTesting() {
        dropTimestampsMs.clear()
    }

    fun isInCooldown(cfg: String, nowMs: Long = System.currentTimeMillis()): Boolean {
        val clean = Converters.cleanUri(cfg)
        val ts = dropTimestampsMs[clean] ?: return false
        return (nowMs - ts) in 0L until COOLDOWN_WINDOW_MS
    }

    /**
     * يحسم قرار التبديل التلقائي:
     * - إذا ماتت عملية النواة (processAlive=false) ننتقل فورًا دون انتظار.
     * - إذا فشل الفحص الأساسي، نتحقق بفحص تأكيدي ثانٍ خلال 600ms على مسار بديل؛
     *   فإن نجح الثاني تجاهلنا الهفوة العابرة، وإن فشل كلاهما انتقلنا خلال ثانيتين.
     */
    fun shouldTriggerFailover(
        processAlive: Boolean,
        primaryProbeOk: Boolean,
        secondaryConfirmOk: Boolean,
    ): Boolean {
        if (!processAlive) return true
        return !primaryProbeOk && !secondaryConfirmOk
    }

    /**
     * يرتب السيرفرات البديلة حسب:
     * 1) استبعاد السيرفر الساقط حاليًا والسيرفرات الواقعة في فترة العزل المؤقت (Cooldown)
     * 2) أولوية سيرفرات VIP المشفّرة الخاصة للمشتركين
     * 3) أعلى سرعة تنزيل مقاسة فعليًا على الهاتف (speedKbps)
     * 4) أقل زمن استجابة (latencyMs)
     */
    fun rankFailoverCandidates(
        excludeCfg: String,
        pool: List<ServerCandidate>,
        nowMs: Long = System.currentTimeMillis(),
        maxCandidates: Int = 16,
    ): List<ServerCandidate> {
        val cleanExclude = Converters.cleanUri(excludeCfg)
        val indexed = pool.mapIndexedNotNull { idx, cand ->
            val clean = Converters.cleanUri(cand.cfg)
            if (clean.isEmpty() || clean == cleanExclude) null else Triple(idx, clean, cand)
        }
        if (indexed.isEmpty()) return emptyList()

        val (inCooldown, ready) = indexed.partition { (_, clean, _) ->
            val ts = dropTimestampsMs[clean]
            ts != null && (nowMs - ts) in 0L until COOLDOWN_WINDOW_MS
        }

        val comparator = Comparator<Triple<Int, String, ServerCandidate>> { a, b ->
            val ca = a.third
            val cb = b.third
            if (ca.isVip != cb.isVip) {
                return@Comparator if (ca.isVip) -1 else 1
            }
            val aHasSpeed = ca.speedKbps > 0.0
            val bHasSpeed = cb.speedKbps > 0.0
            if (aHasSpeed != bHasSpeed) {
                return@Comparator if (aHasSpeed) -1 else 1
            }
            if (aHasSpeed && bHasSpeed && ca.speedKbps != cb.speedKbps) {
                return@Comparator cb.speedKbps.compareTo(ca.speedKbps)
            }
            val aLat = if (ca.latencyMs > 0L) ca.latencyMs else Long.MAX_VALUE
            val bLat = if (cb.latencyMs > 0L) cb.latencyMs else Long.MAX_VALUE
            if (aLat != bLat) {
                return@Comparator aLat.compareTo(bLat)
            }
            a.first.compareTo(b.first)
        }

        val sortedReady = ready.sortedWith(comparator).map { it.third }
        if (sortedReady.size >= maxCandidates || inCooldown.isEmpty()) {
            return sortedReady.take(maxCandidates)
        }

        val sortedFallback = inCooldown
            .sortedBy { (_, clean, _) -> dropTimestampsMs[clean] ?: 0L }
            .map { it.third }

        return (sortedReady + sortedFallback).take(maxCandidates)
    }
}
