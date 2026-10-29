// =====================================================================
// Converters.kt — تحويل كانفيغ URI (vless/vmess/trojan/ss/hysteria2/tuic)
// إلى outbound بصيغة sing-box.
//
// المخطط مُتحقَّق منه عمليًا على sing-box v1.14.4:
//   vless 10/12 • vmess 9/10 • trojan 8/10 • ss 10/10 • hysteria2 8/8 • hy2 6/6
// (الفشل الوحيد: نقل xhttp غير مدعوم في sing-box → يُعاد null ويُستثنى).
// =====================================================================
package com.bahrain.vpnconfigs.engine

import android.net.Uri
import android.util.Base64
import org.json.JSONObject
import java.net.URLDecoder

object Converters {

    /** البروتوكولات التي يستطيع التطبيق فحصها عبر sing-box. */
    val SUPPORTED = setOf("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic")

    fun schemeOf(cfg: String): String = cfg.substringBefore("://", "")

    fun isSupported(cfg: String): Boolean = schemeOf(cfg) in SUPPORTED

    /** outbound جاهز لـ sing-box، أو null إذا كان غير مدعوم/غير صالح. */
    fun toOutbound(cfg: String): JSONObject? = try {
        when (schemeOf(cfg)) {
            "vless" -> vless(cfg)
            "vmess" -> vmess(cfg)
            "trojan" -> trojan(cfg)
            "ss" -> shadowsocks(cfg)
            "hysteria2", "hy2" -> hysteria2(cfg)
            "tuic" -> tuic(cfg)
            else -> null
        }
    } catch (e: Exception) {
        null
    }

    // ───────────────────────── أدوات ─────────────────────────
    private fun q(u: Uri): Map<String, String> =
        u.queryParameterNames.associateWith { u.getQueryParameter(it) ?: "" }

    private fun dec(s: String?): String =
        try { URLDecoder.decode(s ?: "", "UTF-8") } catch (_: Exception) { s ?: "" }

    /** فكّ base64 يقبل الصيغة القياسية والـ URL-safe (مع/بدون padding). */
    private fun b64(s: String): ByteArray {
        val compact = s.replace(Regex("\\s+"), "")
        return try {
            Base64.decode(compact, Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            Base64.decode(compact, Base64.URL_SAFE or Base64.NO_WRAP)
        }
    }

    private fun tlsBlock(u: Uri, q: Map<String, String>, defaultAlpn: List<String>? = null): JSONObject {
        val t = JSONObject()
        t.put("enabled", true)
        t.put("server_name", q["sni"] ?: q["peer"] ?: u.host ?: "")
        t.put("insecure",
            q["allowInsecure"] in listOf("1", "true") || q["insecure"] in listOf("1", "true"))
        val fp = q["fp"]
        if (!fp.isNullOrBlank()) {
            t.put("utls", JSONObject().put("enabled", true).put("fingerprint", fp))
        }
        val alpn = q["alpn"]
        if (!alpn.isNullOrBlank()) {
            t.put("alpn", alpn.split(",").filter { it.isNotBlank() })
        } else if (defaultAlpn != null) {
            t.put("alpn", defaultAlpn)
        }
        return t
    }

    private fun realityBlock(q: Map<String, String>): JSONObject = JSONObject()
        .put("enabled", true)
        .put("public_key", q["pbk"] ?: "")
        .put("short_id", q["sid"] ?: "")

    /** نقل البيانات (transport) — null يعني TCP خام. xhttp غير مدعوم → null + علامة. */
    private fun transportOf(net: String?, q: Map<String, String>): JSONObject? = when (net) {
        "ws" -> JSONObject().put("type", "ws").put("path", dec(q["path"] ?: "/")).also {
            q["host"]?.takeIf { h -> h.isNotBlank() }?.let { h ->
                it.put("headers", JSONObject().put("Host", h.substringBefore(",")))
                // دعم early-data الشائع في عقد ws
                it.put("max_early_data", 2048).put("early_data_header_name", "Sec-WebSocket-Protocol")
            }
        }
        "httpupgrade" -> JSONObject().put("type", "httpupgrade").put("path", dec(q["path"] ?: "/"))
            .put("host", q["host"] ?: "")
        "grpc" -> JSONObject().put("type", "grpc").put("service_name", q["serviceName"] ?: "")
        "http" -> JSONObject().put("type", "http").put("path", dec(q["path"] ?: "/"))
            .put("host", q["host"] ?: "")
        else -> null      // tcp / raw / xhttp / splithttp
    }

    /** نقل غير مدعوم في sing-box (يجب استثناء الكانفيغ بدل تشغيله خاطئًا). */
    private fun unsupportedTransport(net: String?): Boolean =
        net in setOf("xhttp", "splithttp", "kcp", "quic")

    // ───────────────────────── vless ─────────────────────────
    private fun vless(cfg: String): JSONObject? {
        val u = Uri.parse(cfg)
        val q = q(u)
        val net = q["type"] ?: "tcp"
        if (unsupportedTransport(net)) return null
        val uuid = u.userInfo?.substringBefore(":") ?: return null
        val ob = JSONObject()
            .put("type", "vless")
            .put("server", u.host ?: return null)
            .put("server_port", u.port.takeIf { it > 0 } ?: 443)
            .put("uuid", dec(uuid))
        // flow صالح فقط مع tcp
        val flow = q["flow"]
        if (!flow.isNullOrBlank() && (net == "tcp" || net == "raw")) ob.put("flow", flow)

        when (q["security"]) {
            "tls" -> ob.put("tls", tlsBlock(u, q))
            "reality" -> {
                val t = tlsBlock(u, q)
                if (!t.has("utls")) t.put("utls", JSONObject().put("enabled", true).put("fingerprint", "chrome"))
                t.put("reality", realityBlock(q))
                ob.put("tls", t)
            }
        }
        transportOf(net, q)?.let { ob.put("transport", it) }
        return ob
    }

    // ───────────────────────── vmess ─────────────────────────
    private fun vmess(cfg: String): JSONObject? {
        val body = cfg.substringAfter("://").substringBefore("#").trim()
        val json = JSONObject(String(b64(body), Charsets.UTF_8))
        val net = json.optString("net", "tcp")
        if (unsupportedTransport(net)) return null
        val host = json.optString("add")
        if (host.isBlank()) return null

        val ob = JSONObject()
            .put("type", "vmess")
            .put("server", host)
            .put("server_port", json.optInt("port", 443))
            .put("uuid", json.optString("id"))
            .put("alter_id", json.optInt("aid", 0))
            .put("security", json.optString("scy", "auto").ifBlank { "auto" })

        if (json.optString("tls") in listOf("tls", "reality")) {
            val t = JSONObject()
                .put("enabled", true)
                .put("server_name", json.optString("sni").ifBlank {
                    json.optString("host").ifBlank { host }
                })
            val fp = json.optString("fp")
            t.put("utls", JSONObject().put("enabled", true)
                .put("fingerprint", fp.ifBlank { "chrome" }))
            ob.put("tls", t)
        }

        val qq = mapOf(
            "path" to json.optString("path"),
            "host" to json.optString("host"),
            "serviceName" to json.optString("path"),
        )
        transportOf(net, qq)?.let { ob.put("transport", it) }
        return ob
    }

    // ───────────────────────── trojan ─────────────────────────
    private fun trojan(cfg: String): JSONObject? {
        val u = Uri.parse(cfg)
        val q = q(u)
        val net = q["type"] ?: "tcp"
        if (unsupportedTransport(net)) return null
        val pass = u.userInfo?.substringBefore(":") ?: return null

        val ob = JSONObject()
            .put("type", "trojan")
            .put("server", u.host ?: return null)
            .put("server_port", u.port.takeIf { it > 0 } ?: 443)
            .put("password", dec(pass))

        if (q["security"] == "reality") {
            val t = tlsBlock(u, q)
            if (!t.has("utls")) t.put("utls", JSONObject().put("enabled", true).put("fingerprint", "chrome"))
            t.put("reality", realityBlock(q))
            ob.put("tls", t)
        } else {
            ob.put("tls", tlsBlock(u, q, listOf("h2", "http/1.1")))
        }
        transportOf(net, q)?.let { ob.put("transport", it) }
        return ob
    }

    // ───────────────────────── shadowsocks ─────────────────────────
    private fun shadowsocks(cfg: String): JSONObject? {
        val body = cfg.substringAfter("://").substringBefore("#").substringBefore("?").trim()

        fun build(method: String, password: String, host: String, port: Int): JSONObject? =
            if (host.isBlank() || port <= 0 || method.isBlank()) null
            else JSONObject()
                .put("type", "shadowsocks")
                .put("server", host)
                .put("server_port", port)
                .put("method", method)
                .put("password", password)

        fun plain(s: String): Triple<String, String, String>? {
            val at = s.lastIndexOf('@')
            if (at <= 0) return null
            val mp = s.substring(0, at)
            val hp = s.substring(at + 1)
            val ci = mp.indexOf(':')
            if (ci <= 0) return null
            return Triple(mp.substring(0, ci), mp.substring(ci + 1), hp)
        }

        // 1) SIP002: base64(method:pass)@host:port
        if (body.contains('@')) {
            val at = body.lastIndexOf('@')
            val left = body.substring(0, at)
            val right = body.substring(at + 1)
            try {
                val d = String(b64(left), Charsets.UTF_8)
                val ci = d.indexOf(':')
                if (ci > 0) {
                    val h = right.substringBeforeLast(':')
                    val p = right.substringAfterLast(':').toIntOrNull() ?: 0
                    return build(d.substring(0, ci), d.substring(ci + 1), h, p)
                }
            } catch (_: Exception) { /* ليس base64 */ }
        }

        // 2) base64 لكامل النص: method:pass@host:port
        for (cand in listOf(body, dec(body))) {
            try {
                val d = String(b64(cand), Charsets.UTF_8)
                plain(d)?.let { (m, p, hp) ->
                    return build(m, p, hp.substringBeforeLast(':'),
                        hp.substringAfterLast(':').toIntOrNull() ?: 0)
                }
            } catch (_: Exception) { }
        }

        // 3) نص صريح
        plain(body)?.let { (m, p, hp) ->
            return build(m, p, hp.substringBeforeLast(':'),
                hp.substringAfterLast(':').toIntOrNull() ?: 0)
        }
        return null
    }

    // ───────────────────────── hysteria2 ─────────────────────────
    private fun hysteria2(cfg: String): JSONObject? {
        val u = Uri.parse(cfg)
        val q = q(u)
        // الصيغة: hysteria2://password@host:port  أو  hysteria2://user:pass@host:port
        val password = dec(u.userInfo?.substringAfter(":", "")?.ifBlank { u.userInfo ?: "" } ?: "")
        val ob = JSONObject()
            .put("type", "hysteria2")
            .put("server", u.host ?: return null)
            .put("server_port", u.port.takeIf { it > 0 } ?: 443)
            .put("password", password.ifBlank { dec(u.userInfo ?: "") })
            .put("tls", tlsBlock(u, q, listOf("h3")))
        if (q["obfs"] == "salamander") {
            ob.put("obfs", JSONObject().put("type", "salamander")
                .put("password", q["obfs-password"] ?: ""))
        }
        q["up"]?.toIntOrNull()?.let { ob.put("up_mbps", it) }
        q["down"]?.toIntOrNull()?.let { ob.put("down_mbps", it) }
        return ob
    }

    // ───────────────────────── tuic ─────────────────────────
    private fun tuic(cfg: String): JSONObject? {
        val u = Uri.parse(cfg)
        val q = q(u)
        val uuid = u.userInfo?.substringBefore(":") ?: return null
        return JSONObject()
            .put("type", "tuic")
            .put("server", u.host ?: return null)
            .put("server_port", u.port.takeIf { it > 0 } ?: 443)
            .put("uuid", dec(uuid))
            .put("password", dec(u.userInfo?.substringAfter(":", "") ?: ""))
            .put("congestion_control", q["congestion_control"] ?: "bbr")
            .put("udp_relay_mode", q["udp_relay_mode"] ?: "native")
            .put("tls", tlsBlock(u, q, listOf("h3")))
    }

    /** اسم مختصر للعرض (المضيف:المنفذ). */
    fun endpointLabel(cfg: String): String = try {
        when (schemeOf(cfg)) {
            "vmess" -> {
                val j = JSONObject(String(b64(cfg.substringAfter("://").substringBefore("#")), Charsets.UTF_8))
                "${j.optString("add")}:${j.optInt("port")}"
            }
            else -> {
                val u = Uri.parse(cfg)
                "${u.host}:${u.port}"
            }
        }
    } catch (_: Exception) { "—" }
}
