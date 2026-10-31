package com.bahrain.vpnconfigs.engine

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Raw observations from the network probes (all measured outside the VPN tunnel). */
data class ProbeObservations(
    val systemDnsIps: List<String>,      // what the device resolver returns for the blocked domain
    val dohIps: List<String>,            // what encrypted DNS (DoH) returns for it
    val sniBlockedOk: Boolean,           // TLS to neutral host with blocked SNI succeeded
    val sniControlOk: Boolean,           // TLS to same neutral host with harmless SNI succeeded
    val ipDirectOk: Boolean,             // TCP connect to the blocked domain's real IP succeeded
    val udpOk: Boolean,                  // UDP DNS query to a public resolver got an answer
    val internetOk: Boolean,             // basic control connection works at all
)

enum class BlockType { DNS, SNI, IP, UDP }

data class BlockingProfile(
    val measuredAtMs: Long,
    val networkType: String,
    val internetOk: Boolean,
    val blocks: Set<BlockType>,
    /** Score adjustment per URI scheme ("vless-reality" is a pseudo-scheme for Reality configs). */
    val protocolBonus: Map<String, Double>,
) {
    fun toJson(): String = JSONObject()
        .put("measured_at_ms", measuredAtMs)
        .put("network_type", networkType)
        .put("internet_ok", internetOk)
        .put("blocks", JSONArray(blocks.map { it.name }))
        .put("bonus", JSONObject(protocolBonus))
        .toString()

    companion object {
        fun fromJson(raw: String?): BlockingProfile? = runCatching {
            if (raw.isNullOrBlank()) return null
            val o = JSONObject(raw)
            val b = o.optJSONArray("blocks") ?: JSONArray()
            val bonus = o.optJSONObject("bonus") ?: JSONObject()
            BlockingProfile(
                measuredAtMs = o.optLong("measured_at_ms"),
                networkType = o.optString("network_type", "UNKNOWN"),
                internetOk = o.optBoolean("internet_ok", true),
                blocks = (0 until b.length()).mapNotNull { runCatching { BlockType.valueOf(b.getString(it)) }.getOrNull() }.toSet(),
                protocolBonus = bonus.keys().asSequence().associateWith { bonus.optDouble(it, 0.0) },
            )
        }.getOrNull()
    }
}

object CensorshipProbe {
    const val BLOCKED_DOMAIN = "www.youtube.com"
    const val CONTROL_DOMAIN = "www.cloudflare.com"
    private const val NEUTRAL_TLS_IP = "1.1.1.1"
    private const val TIMEOUT_MS = 4000

    /** Max age before a profile is ignored by ranking (networks change). */
    const val PROFILE_TTL_MS = 6 * 60 * 60 * 1000L

    /** Turns observations into a profile. Pure function — unit tested. */
    fun classify(obs: ProbeObservations, networkType: String, nowMs: Long = System.currentTimeMillis()): BlockingProfile {
        if (!obs.internetOk) return BlockingProfile(nowMs, networkType, false, emptySet(), emptyMap())
        val blocks = mutableSetOf<BlockType>()
        val dohSet = obs.dohIps.toSet()
        val dnsTampered = obs.dohIps.isNotEmpty() && (
            obs.systemDnsIps.isEmpty() ||
                obs.systemDnsIps.any { isBogon(it) } ||
                obs.systemDnsIps.none { it in dohSet } && obs.systemDnsIps.all { isPrivate(it) }
            )
        if (dnsTampered) blocks += BlockType.DNS
        if (obs.sniControlOk && !obs.sniBlockedOk) blocks += BlockType.SNI
        if (obs.dohIps.isNotEmpty() && !obs.ipDirectOk) blocks += BlockType.IP
        if (!obs.udpOk) blocks += BlockType.UDP

        val bonus = mutableMapOf<String, Double>()
        if (BlockType.SNI in blocks) {
            // Active DPI on TLS SNI: Reality borrows an allowed SNI and resists it best.
            bonus["vless-reality"] = 8.0
            bonus["vmess"] = -3.0
        }
        if (BlockType.UDP in blocks) {
            // QUIC-based protocols cannot work without UDP.
            bonus["hysteria2"] = -15.0
            bonus["hy2"] = -15.0
            bonus["tuic"] = -15.0
        } else if (BlockType.SNI in blocks || BlockType.IP in blocks) {
            // UDP passes while TCP/TLS is filtered: QUIC transports often slip through.
            bonus["hysteria2"] = 5.0
            bonus["hy2"] = 5.0
            bonus["tuic"] = 4.0
        }
        if (BlockType.IP in blocks) {
            // Direct IPs are blocked: servers behind a shared CDN address are the most likely to work.
            bonus["cdn"] = 7.0
        }
        return BlockingProfile(nowMs, networkType, true, blocks, bonus)
    }

    /** Bonus for one config, accounting for Reality inside VLESS. */
    fun bonusFor(cfg: String, profile: BlockingProfile?, nowMs: Long = System.currentTimeMillis()): Double {
        if (profile == null || profile.protocolBonus.isEmpty() || nowMs - profile.measuredAtMs > PROFILE_TTL_MS) return 0.0
        val scheme = cfg.substringBefore("://").lowercase()
        val isReality = scheme == "vless" && cfg.contains("security=reality", ignoreCase = true)
        val base = (if (isReality) profile.protocolBonus["vless-reality"] else null)
            ?: profile.protocolBonus[scheme] ?: 0.0
        val cdn = profile.protocolBonus["cdn"]?.takeIf { CdnDetector.isCdnFronted(cfg) } ?: 0.0
        return base + cdn
    }

    /** Runs all probes on the current (non-VPN) network. Call only while the VPN is off. */
    suspend fun observe(): ProbeObservations = withContext(Dispatchers.IO) {
        val internetOk = tcpOk(NEUTRAL_TLS_IP, 443)
        val sys = runCatching { InetAddress.getAllByName(BLOCKED_DOMAIN).map { it.hostAddress.orEmpty() } }.getOrDefault(emptyList())
        val doh = dohResolve(BLOCKED_DOMAIN)
        ProbeObservations(
            systemDnsIps = sys,
            dohIps = doh,
            sniBlockedOk = tlsOk(NEUTRAL_TLS_IP, BLOCKED_DOMAIN),
            sniControlOk = tlsOk(NEUTRAL_TLS_IP, CONTROL_DOMAIN),
            ipDirectOk = doh.firstOrNull()?.let { tcpOk(it, 443) } ?: false,
            udpOk = udpDnsOk("8.8.8.8") || udpDnsOk("1.1.1.1"),
            internetOk = internetOk,
        )
    }

    private fun tcpOk(ip: String, port: Int): Boolean = runCatching {
        Socket().use { it.connect(InetSocketAddress(ip, port), TIMEOUT_MS) }
        true
    }.getOrDefault(false)

    private fun tlsOk(ip: String, sni: String): Boolean = runCatching {
        val raw = Socket().apply { connect(InetSocketAddress(ip, 443), TIMEOUT_MS); soTimeout = TIMEOUT_MS }
        (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, ip, 443, true).use { s ->
            s as SSLSocket
            s.sslParameters = s.sslParameters.apply { serverNames = listOf(SNIHostName(sni)) }
            // A filtered SNI shows up as a reset/timeout during the handshake. Certificate
            // mismatch is expected here (neutral host) and still proves the handshake got through.
            runCatching { s.startHandshake() }.exceptionOrNull()?.let { e ->
                if (e !is javax.net.ssl.SSLHandshakeException || e.message?.contains("reset", true) == true) throw e
            }
        }
        true
    }.getOrDefault(false)

    private fun dohResolve(name: String): List<String> = runCatching {
        val c = URL("https://$NEUTRAL_TLS_IP/dns-query?name=$name&type=A").openConnection() as HttpURLConnection
        c.connectTimeout = TIMEOUT_MS
        c.readTimeout = TIMEOUT_MS
        c.setRequestProperty("accept", "application/dns-json")
        c.inputStream.use { ins ->
            val ans = JSONObject(ins.readBytes().toString(Charsets.UTF_8)).optJSONArray("Answer") ?: JSONArray()
            (0 until ans.length()).map { ans.getJSONObject(it) }.filter { it.optInt("type") == 1 }.map { it.optString("data") }
        }
    }.getOrDefault(emptyList())

    private fun udpDnsOk(server: String): Boolean = runCatching {
        // Minimal DNS query for "example.com" A record.
        val q = byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7) + "example".toByteArray() +
            byteArrayOf(3) + "com".toByteArray() + byteArrayOf(0, 0, 1, 0, 1)
        DatagramSocket().use { s ->
            s.soTimeout = TIMEOUT_MS
            s.send(DatagramPacket(q, q.size, InetAddress.getByName(server), 53))
            val buf = ByteArray(512)
            s.receive(DatagramPacket(buf, buf.size))
            buf[0] == 0x12.toByte() && buf[1] == 0x34.toByte()
        }
    }.getOrDefault(false)

    internal fun isPrivate(ip: String): Boolean =
        ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") ||
            Regex("^172\\.(1[6-9]|2\\d|3[01])\\.").containsMatchIn(ip)

    internal fun isBogon(ip: String): Boolean = ip == "0.0.0.0" || ip == "::" || ip.startsWith("10.10.34.")
}
