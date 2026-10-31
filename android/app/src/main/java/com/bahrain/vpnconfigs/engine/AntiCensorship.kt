package com.bahrain.vpnconfigs.engine

import org.json.JSONObject
import java.util.Base64

/** TLS ClientHello fragmentation (sing-box 1.12+ `tls.fragment`) — splits the SNI across TCP segments. */
object TlsFragment {
    const val MODE_AUTO = "AUTO"
    const val MODE_ON = "ON"
    const val MODE_OFF = "OFF"

    /** AUTO enables it only when the last probe on this network found SNI filtering. */
    fun shouldEnable(
        mode: String,
        profile: BlockingProfile?,
        networkType: String?,
        nowMs: Long = System.currentTimeMillis(),
    ): Boolean = when (mode.uppercase()) {
        MODE_ON -> true
        MODE_OFF -> false
        else -> profile != null &&
            nowMs - profile.measuredAtMs <= CensorshipProbe.PROFILE_TTL_MS &&
            (networkType == null || profile.networkType.equals(networkType, ignoreCase = true)) &&
            BlockType.SNI in profile.blocks
    }

    /**
     * Adds fragmentation to a sing-box outbound when it is meaningful: TCP-based TLS only.
     * Skipped for Reality (own handshake) and QUIC protocols (Hysteria2/TUIC). Returns true if applied.
     */
    fun apply(outbound: JSONObject): Boolean {
        val type = outbound.optString("type")
        if (type in setOf("hysteria2", "tuic", "wireguard")) return false
        val tls = outbound.optJSONObject("tls") ?: return false
        if (!tls.optBoolean("enabled")) return false
        if (tls.optJSONObject("reality")?.optBoolean("enabled") == true) return false
        tls.put("fragment", true)
        tls.put("fragment_fallback_delay", "500ms")
        return true
    }
}

/**
 * Recognizes configs routed through Cloudflare's CDN (WebSocket / gRPC / HTTPUpgrade on Cloudflare
 * ports or Cloudflare IPs). Such servers hide behind shared CDN addresses, so they survive IP blocking.
 */
object CdnDetector {
    private val CF_TLS_PORTS = setOf(443, 2053, 2083, 2087, 2096, 8443)
    private val CF_PLAIN_PORTS = setOf(80, 8080, 8880, 2052, 2082, 2086, 2095)
    private val CDN_TRANSPORTS = setOf("ws", "grpc", "httpupgrade")

    // Cloudflare published IPv4 ranges (https://www.cloudflare.com/ips-v4/).
    private val CF_V4 = listOf(
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ).map { cidr ->
        val (ip, bits) = cidr.split("/")
        ipToLong(ip)!! to bits.toInt()
    }

    private fun ipToLong(ip: String): Long? {
        val p = ip.split(".")
        if (p.size != 4) return null
        return p.fold(0L) { acc, s -> val n = s.toIntOrNull() ?: return null; if (n !in 0..255) return null; (acc shl 8) or n.toLong() }
    }

    fun isCloudflareIp(host: String): Boolean {
        val v = ipToLong(host.trim()) ?: return false
        return CF_V4.any { (base, bits) -> val mask = (-1L shl (32 - bits)) and 0xFFFFFFFFL; (v and mask) == (base and mask) }
    }

    private data class Parsed(val host: String, val port: Int, val transport: String, val tls: Boolean)

    private fun parse(cfg: String): Parsed? = runCatching {
        val clean = cfg.trim().substringBefore("#")
        when (clean.substringBefore("://").lowercase()) {
            "vless", "trojan" -> {
                val rest = clean.substringAfter("://")
                val authority = rest.substringBefore("?").substringBefore("/").substringAfterLast("@")
                val host = if (authority.startsWith("[")) authority.substringBefore("]").removePrefix("[") else authority.substringBeforeLast(":")
                val port = authority.substringAfterLast(":").toIntOrNull() ?: 443
                val q = rest.substringAfter("?", "").split("&").mapNotNull {
                    val k = it.substringBefore("=", ""); if (k.isEmpty()) null else k to it.substringAfter("=")
                }.toMap()
                val sec = q["security"]?.lowercase().orEmpty()
                val isTrojan = clean.startsWith("trojan", ignoreCase = true)
                Parsed(host, port, q["type"]?.lowercase().orEmpty(), sec == "tls" || (isTrojan && sec != "none"))
            }
            "vmess" -> {
                val body = clean.substringAfter("://")
                val json = JSONObject(String(Base64.getDecoder().decode(body.padEnd((body.length + 3) / 4 * 4, '='))))
                Parsed(
                    json.optString("add"),
                    json.optString("port").toIntOrNull() ?: json.optInt("port", 443),
                    json.optString("net").lowercase(),
                    json.optString("tls").lowercase() == "tls",
                )
            }
            else -> null
        }
    }.getOrNull()

    fun isCdnFronted(cfg: String): Boolean {
        val p = parse(cfg) ?: return false
        if (p.transport !in CDN_TRANSPORTS) return false
        if (isCloudflareIp(p.host)) return true
        return if (p.tls) p.port in CF_TLS_PORTS else p.port in CF_PLAIN_PORTS
    }
}
