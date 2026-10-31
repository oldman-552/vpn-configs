package com.bahrain.vpnconfigs.engine

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.time.Instant
import java.util.Base64
import java.util.concurrent.TimeUnit

/** Free Cloudflare WARP account (WireGuard) stored locally on the device. */
data class WarpAccount(
    val privateKey: String,
    val peerPublicKey: String,
    val addressV4: String,
    val addressV6: String,
    val reserved: List<Int>,
    val endpointIp: String = WarpManager.DEFAULT_ENDPOINT_IP,
    val endpointPort: Int = WarpManager.DEFAULT_ENDPOINT_PORT,
) {
    fun toJson(): String = JSONObject()
        .put("private_key", privateKey).put("peer_public_key", peerPublicKey)
        .put("v4", addressV4).put("v6", addressV6)
        .put("reserved", JSONArray(reserved))
        .put("endpoint_ip", endpointIp).put("endpoint_port", endpointPort)
        .toString()

    /** sing-box 1.11+ WireGuard endpoint, tagged so routing treats it like the proxy outbound. */
    fun toSingBoxEndpoint(tag: String = "proxy"): JSONObject {
        val addrs = JSONArray().put("$addressV4/32")
        if (addressV6.isNotBlank()) addrs.put("$addressV6/128")
        return JSONObject()
            .put("type", "wireguard")
            .put("tag", tag)
            .put("mtu", 1280)
            .put("address", addrs)
            .put("private_key", privateKey)
            .put(
                "peers",
                JSONArray().put(
                    JSONObject()
                        .put("address", endpointIp)
                        .put("port", endpointPort)
                        .put("public_key", peerPublicKey)
                        .put("allowed_ips", JSONArray().put("0.0.0.0/0").put("::/0"))
                        .put("reserved", JSONArray(reserved)),
                ),
            )
    }

    companion object {
        fun fromJson(raw: String?): WarpAccount? = runCatching {
            if (raw.isNullOrBlank()) return null
            val o = JSONObject(raw)
            val r = o.getJSONArray("reserved")
            WarpAccount(
                o.getString("private_key"), o.getString("peer_public_key"),
                o.getString("v4"), o.optString("v6"),
                (0 until r.length()).map { r.getInt(it) },
                o.optString("endpoint_ip", WarpManager.DEFAULT_ENDPOINT_IP),
                o.optInt("endpoint_port", WarpManager.DEFAULT_ENDPOINT_PORT),
            )
        }.getOrNull()
    }
}

object WarpManager {
    /** Pseudo-config handled by SingBox.buildConfig instead of Converters. */
    const val WARP_URI = "warp://cloudflare"
    const val LABEL = "Cloudflare WARP"
    const val DEFAULT_ENDPOINT_IP = "162.159.192.1"
    const val DEFAULT_ENDPOINT_PORT = 2408
    private const val REG_URL = "https://api.cloudflareclient.com/v0a2158/reg"

    fun isWarp(cfg: String?): Boolean = cfg?.trim()?.lowercase()?.startsWith("warp://") == true

    /** Generates a WireGuard key pair with the bundled sing-box binary. Returns (private, public). */
    fun generateKeyPair(singBoxBinary: String): Pair<String, String>? = runCatching {
        val proc = ProcessBuilder(singBoxBinary, "generate", "wg-keypair").redirectErrorStream(true).start()
        if (!proc.waitFor(10, TimeUnit.SECONDS)) { proc.destroy(); return null }
        parseKeyPair(proc.inputStream.bufferedReader().readText())
    }.getOrNull()

    /** Parses `sing-box generate wg-keypair` output ("PrivateKey: …" / "PublicKey: …"). */
    fun parseKeyPair(out: String): Pair<String, String>? {
        val priv = Regex("PrivateKey:\\s*(\\S+)").find(out)?.groupValues?.get(1)
        val pub = Regex("PublicKey:\\s*(\\S+)").find(out)?.groupValues?.get(1)
        return if (priv != null && pub != null) priv to pub else null
    }

    /** Parses Cloudflare's registration response into an account. Pure — unit tested. */
    fun parseRegistration(body: String, privateKey: String): WarpAccount? = runCatching {
        val cfg = JSONObject(body).getJSONObject("config")
        val peer = cfg.getJSONArray("peers").getJSONObject(0)
        val addrs = cfg.getJSONObject("interface").getJSONObject("addresses")
        val reserved = Base64.getDecoder().decode(cfg.optString("client_id", ""))
            .take(3).map { it.toInt() and 0xFF }.ifEmpty { listOf(0, 0, 0) }
        val epV4 = peer.optJSONObject("endpoint")?.optString("v4").orEmpty().substringBefore(":")
        WarpAccount(
            privateKey = privateKey,
            peerPublicKey = peer.getString("public_key"),
            addressV4 = addrs.getString("v4"),
            addressV6 = addrs.optString("v6"),
            reserved = reserved,
            endpointIp = epV4.takeIf { it.matches(Regex("\\d+\\.\\d+\\.\\d+\\.\\d+")) } ?: DEFAULT_ENDPOINT_IP,
        )
    }.getOrNull()

    /** Registers a new free WARP device. Network call — run off the main thread, while the VPN is off. */
    fun register(singBoxBinary: String): Result<WarpAccount> = runCatching {
        val (priv, pub) = generateKeyPair(singBoxBinary) ?: error("keygen failed")
        val body = JSONObject()
            .put("key", pub).put("install_id", "").put("fcm_token", "")
            .put("tos", Instant.now().toString()).put("type", "Android")
            .put("model", "PC").put("locale", "en_US").put("warp_enabled", true)
            .toString()
        val c = URL(REG_URL).openConnection() as HttpURLConnection
        c.requestMethod = "POST"
        c.connectTimeout = 10_000
        c.readTimeout = 10_000
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/json; charset=UTF-8")
        c.setRequestProperty("User-Agent", "okhttp/3.12.1")
        c.setRequestProperty("CF-Client-Version", "a-6.30-2158")
        c.outputStream.use { it.write(body.toByteArray()) }
        val code = c.responseCode
        val resp = (if (code in 200..299) c.inputStream else c.errorStream)?.use { it.readBytes().toString(Charsets.UTF_8) }.orEmpty()
        if (code !in 200..299) error("HTTP $code")
        parseRegistration(resp, priv) ?: error("bad response")
    }
}
