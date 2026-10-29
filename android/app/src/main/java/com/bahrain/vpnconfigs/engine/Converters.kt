// =====================================================================
// Converters.kt — تحويل كانفيغ URI (vless/vmess/trojan/ss/hysteria2/tuic)
// إلى outbound بصيغة sing-box.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import android.net.Uri
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLDecoder
import java.util.concurrent.ConcurrentHashMap

object Converters {

    /** البروتوكولات التي يستطيع التطبيق فحصها وتشغيلها عبر sing-box. */
    val SUPPORTED = setOf("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic")

    private val INVISIBLE_RE = Regex("[\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u206F\\uFEFF]+")
    private val WS_ED_RE = Regex("^(.*?)\\?ed=(\\d+)$")

    private data class MetaCache(val supported: Boolean, val host: String, val endpoint: String)
    private val metaCache = ConcurrentHashMap<String, MetaCache>()

    fun cleanUri(raw: String): String =
        raw.replace("&amp;", "&")
            .replace(INVISIBLE_RE, "")
            .trim()
            .substringBefore("#")
            .trim()

    fun schemeOf(cfg: String): String = cleanUri(cfg).substringBefore("://", "").lowercase()

    private fun metaOf(cfg: String): MetaCache {
        val cleaned = cleanUri(cfg)
        metaCache[cleaned]?.let { return it }
        val ob = toOutbound(cleaned)
        val supported = ob != null
        val host = ob?.optString("server", "")?.lowercase() ?: ""
        val endpoint = if (ob != null) {
            val srv = ob.optString("server")
            val port = if (ob.has("server_port")) {
                ob.optInt("server_port").toString()
            } else {
                ob.optJSONArray("server_ports")?.optString(0)?.replace(':', '-') ?: "443"
            }
            "$srv:$port"
        } else {
            runCatching {
                val u = Uri.parse(cleaned)
                val h = stripBrackets(u.host)
                val p = u.port.takeIf { it > 0 } ?: 443
                if (h.isNotBlank()) "$h:$p" else "—"
            }.getOrDefault("—")
        }
        val entry = MetaCache(supported, host, endpoint)
        if (metaCache.size > 4096) metaCache.clear()
        metaCache[cleaned] = entry
        return entry
    }

    /** يتحقّق فعليًا من قابلية تحويل الكانفيغ بالكامل إلى outbound صالح لـ sing-box (وليس المخطط فقط). */
    fun isSupported(cfg: String): Boolean = schemeOf(cfg) in SUPPORTED && metaOf(cfg).supported

    /** outbound جاهز لـ sing-box، أو null إذا كان غير مدعوم/غير صالح. */
    fun toOutbound(cfg: String): JSONObject? = try {
        val cleaned = cleanUri(cfg)
        when (schemeOf(cleaned)) {
            "vless" -> vless(cleaned)
            "vmess" -> vmess(cleaned)
            "trojan" -> trojan(cleaned)
            "ss" -> shadowsocks(cleaned)
            "hysteria2", "hy2" -> hysteria2(cleaned)
            "tuic" -> tuic(cleaned)
            else -> null
        }
    } catch (_: Exception) {
        null
    }

    // ───────────────────────── أدوات ─────────────────────────
    private fun q(u: Uri): Map<String, String> = try {
        parseQueryString(u.encodedQuery ?: "")
    } catch (_: Exception) {
        emptyMap()
    }

    /** فكّ ترميز النسبة المئوية (%XX) وفق RFC 3986 دون إفساد الرمز '+' إلى مسافة. */
    private fun dec(s: String?): String =
        try { URLDecoder.decode((s ?: "").replace("+", "%2B"), "UTF-8") } catch (_: Exception) { s ?: "" }

    private fun stripBrackets(host: String?): String =
        (host ?: "").trim().removeSurrounding("[", "]")

    private fun validPort(port: Int): Boolean = port in 1..65535

    /** فكّ base64 يقبل الصيغة القياسية والـ URL-safe (مع/بدون padding). */
    private fun b64(s: String): ByteArray {
        val compact = s.replace(Regex("\\s+"), "")
            .replace('-', '+')
            .replace('_', '/')
        if (compact.isEmpty()) throw IllegalArgumentException("empty base64")
        val padded = compact + "=".repeat((4 - compact.length % 4) % 4)
        return Base64.decode(padded, Base64.DEFAULT)
    }

    private fun jsonArrayOfStrings(items: List<String>): JSONArray = JSONArray().apply {
        items.forEach { if (it.isNotBlank()) put(it.trim()) }
    }

    private fun tlsBlock(
        host: String,
        q: Map<String, String>,
        defaultAlpn: List<String>? = null,
    ): JSONObject {
        val t = JSONObject()
        t.put("enabled", true)
        val sni = (q["sni"] ?: q["peer"] ?: "").ifBlank { host }
        t.put("server_name", sni)
        t.put(
            "insecure",
            q["allowInsecure"] in listOf("1", "true") || q["insecure"] in listOf("1", "true"),
        )
        val fp = q["fp"]?.trim()
        if (!fp.isNullOrBlank() && !fp.equals("none", ignoreCase = true)) {
            t.put("utls", JSONObject().put("enabled", true).put("fingerprint", fp))
        }
        val alpnRaw = q["alpn"]
        if (!alpnRaw.isNullOrBlank()) {
            val list = alpnRaw.split(",").map { it.trim() }.filter { it.isNotBlank() }
            if (list.isNotEmpty()) t.put("alpn", jsonArrayOfStrings(list))
        } else if (!defaultAlpn.isNullOrEmpty()) {
            t.put("alpn", jsonArrayOfStrings(defaultAlpn))
        }
        return t
    }

    private fun realityBlock(q: Map<String, String>): JSONObject = JSONObject()
        .put("enabled", true)
        .put("public_key", q["pbk"] ?: "")
        .put("short_id", q["sid"] ?: "")

    /** نقل البيانات (transport) — null يعني TCP خام. */
    private fun transportOf(net: String?, q: Map<String, String>): JSONObject? = when (net) {
        "ws" -> {
            val rawPath = dec(q["path"] ?: "/").ifBlank { "/" }
            val match = WS_ED_RE.matchEntire(rawPath)
            val cleanPath = if (match != null) match.groupValues[1].ifBlank { "/" } else rawPath
            val edFromPath = match?.groupValues?.getOrNull(2)?.toIntOrNull()
            val edFromQuery = q["ed"]?.toIntOrNull()
            val ed = edFromPath ?: edFromQuery

            JSONObject().put("type", "ws").put("path", cleanPath).also { ws ->
                q["host"]?.takeIf { h -> h.isNotBlank() }?.let { h ->
                    ws.put("headers", JSONObject().put("Host", h.substringBefore(",").trim()))
                }
                if (ed != null && ed > 0) {
                    ws.put("max_early_data", ed)
                    ws.put("early_data_header_name", "Sec-WebSocket-Protocol")
                }
            }
        }
        "httpupgrade" -> JSONObject()
            .put("type", "httpupgrade")
            .put("path", dec(q["path"] ?: "/").ifBlank { "/" })
            .apply {
                q["host"]?.takeIf { it.isNotBlank() }?.let {
                    put("host", it.substringBefore(",").trim())
                }
            }
        "grpc" -> JSONObject()
            .put("type", "grpc")
            .put("service_name", q["serviceName"] ?: "")
        "http" -> JSONObject()
            .put("type", "http")
            .put("path", dec(q["path"] ?: "/").ifBlank { "/" })
            .apply {
                val hosts = (q["host"] ?: "").split(",").map { it.trim() }.filter { it.isNotBlank() }
                if (hosts.isNotEmpty()) put("host", jsonArrayOfStrings(hosts))
            }
        else -> null
    }

    /** نقل غير مدعوم في sing-box (يجب استثناء الكانفيغ بدل تشغيله خاطئًا). */
    private fun unsupportedTransport(net: String?): Boolean =
        net in setOf("xhttp", "splithttp", "kcp", "quic")

    // ───────────────────────── vless ─────────────────────────
    private fun vless(cfg: String): JSONObject? {
        val u = Uri.parse(cfg)
        val q = q(u)
        val net = (q["type"] ?: "tcp").lowercase()
        if (unsupportedTransport(net)) return null
        val host = stripBrackets(u.host)
        if (host.isBlank()) return null
        val port = u.port.takeIf { it > 0 } ?: 443
        if (!validPort(port)) return null
        val uuid = dec(u.encodedUserInfo?.substringBefore(":")).trim()
        if (uuid.isBlank()) return null

        val ob = JSONObject()
            .put("type", "vless")
            .put("server", host)
            .put("server_port", port)
            .put("uuid", uuid)

        val flow = q["flow"]?.trim()
        if (!flow.isNullOrBlank() && (net == "tcp" || net == "raw")) {
            ob.put("flow", flow)
        }

        when (q["security"]?.lowercase()) {
            "tls" -> ob.put("tls", tlsBlock(host, q))
            "reality" -> {
                val t = tlsBlock(host, q)
                if (!t.has("utls")) {
                    t.put("utls", JSONObject().put("enabled", true).put("fingerprint", "chrome"))
                }
                t.put("reality", realityBlock(q))
                ob.put("tls", t)
            }
        }
        transportOf(net, q)?.let { ob.put("transport", it) }
        return ob
    }

    // ───────────────────────── vmess ─────────────────────────
    private fun vmess(cfg: String): JSONObject? {
        val body = cfg.substringAfter("://").substringBefore("?").trim()
        val json = JSONObject(String(b64(body), Charsets.UTF_8))
        val net = json.optString("net", "tcp").ifBlank { "tcp" }.lowercase()
        if (unsupportedTransport(net)) return null
        val host = stripBrackets(json.optString("add"))
        val uuid = json.optString("id").trim()
        val port = json.optString("port").trim().toIntOrNull() ?: json.optInt("port", 443)
        val aid = json.optString("aid").trim().toIntOrNull() ?: json.optInt("aid", 0)
        if (host.isBlank() || uuid.isBlank() || !validPort(port)) return null

        val ob = JSONObject()
            .put("type", "vmess")
            .put("server", host)
            .put("server_port", port)
            .put("uuid", uuid)
            .put("alter_id", aid)
            .put("security", json.optString("scy", "auto").ifBlank { "auto" })

        val tlsVal = json.optString("tls").trim().lowercase()
        if (tlsVal in listOf("tls", "reality", "true", "1")) {
            val sni = json.optString("sni").ifBlank {
                json.optString("host").substringBefore(",").trim().ifBlank { host }
            }
            val insecure = json.optString("allowInsecure").lowercase() in listOf("1", "true") ||
                json.optBoolean("allowInsecure", false)
            val t = JSONObject()
                .put("enabled", true)
                .put("server_name", sni)
                .put("insecure", insecure)
            val fp = json.optString("fp").trim()
            val chosenFp = if (fp.isBlank() || fp.equals("none", true)) "chrome" else fp
            t.put("utls", JSONObject().put("enabled", true).put("fingerprint", chosenFp))
            val alpn = json.optString("alpn")
            if (alpn.isNotBlank()) {
                val list = alpn.split(",").map { it.trim() }.filter { it.isNotBlank() }
                if (list.isNotEmpty()) t.put("alpn", jsonArrayOfStrings(list))
            }
            ob.put("tls", t)
        }

        val netType = if (net == "tcp" && json.optString("type").equals("http", true)) "http" else net
        val qq = mapOf(
            "path" to json.optString("path"),
            "host" to json.optString("host"),
            "serviceName" to json.optString("path"),
        )
        transportOf(netType, qq)?.let { ob.put("transport", it) }
        return ob
    }

    // ───────────────────────── trojan ─────────────────────────
    private fun trojan(cfg: String): JSONObject? {
        val u = Uri.parse(cfg)
        val q = q(u)
        val net = (q["type"] ?: "tcp").lowercase()
        if (unsupportedTransport(net)) return null
        val host = stripBrackets(u.host)
        val port = u.port.takeIf { it > 0 } ?: 443
        val pass = dec(u.encodedUserInfo?.substringBefore(":"))
        if (host.isBlank() || pass.isEmpty() || !validPort(port)) return null

        val ob = JSONObject()
            .put("type", "trojan")
            .put("server", host)
            .put("server_port", port)
            .put("password", pass)

        when (q["security"]?.lowercase()) {
            "none" -> { /* بلا TLS */ }
            "reality" -> {
                val t = tlsBlock(host, q)
                if (!t.has("utls")) {
                    t.put("utls", JSONObject().put("enabled", true).put("fingerprint", "chrome"))
                }
                t.put("reality", realityBlock(q))
                ob.put("tls", t)
            }
            else -> ob.put("tls", tlsBlock(host, q, listOf("h2", "http/1.1")))
        }
        transportOf(net, q)?.let { ob.put("transport", it) }
        return ob
    }

    // ───────────────────────── shadowsocks ─────────────────────────
    private fun shadowsocks(cfg: String): JSONObject? {
        val afterScheme = cfg.substringAfter("://").trim()
        val queryPart = afterScheme.substringAfter("?", "")
        if (queryPart.contains("plugin=", ignoreCase = true)) return null
        val body = afterScheme.substringBefore("?").trimEnd('/')

        fun build(method: String, password: String, rawHost: String, port: Int): JSONObject? {
            val host = stripBrackets(rawHost)
            val m = method.trim()
            if (host.isBlank() || !validPort(port) || m.isBlank()) return null
            return JSONObject()
                .put("type", "shadowsocks")
                .put("server", host)
                .put("server_port", port)
                .put("method", m)
                .put("password", password)
        }

        fun splitHostPort(hpRaw: String): Pair<String, Int> {
            val hp = hpRaw.trimEnd('/')
            val h = hp.substringBeforeLast(':')
            val p = hp.substringAfterLast(':').toIntOrNull() ?: 0
            return h to p
        }

        fun plain(s: String): Triple<String, String, String>? {
            val at = s.lastIndexOf('@')
            if (at <= 0) return null
            val mp = s.substring(0, at)
            val hp = s.substring(at + 1).trimEnd('/')
            val ci = mp.indexOf(':')
            if (ci <= 0) return null
            return Triple(mp.substring(0, ci), mp.substring(ci + 1), hp)
        }

        // 1) SIP002: base64(method:pass)@host:port أو method:pass@host:port
        if (body.contains('@')) {
            val at = body.lastIndexOf('@')
            val left = body.substring(0, at)
            val right = body.substring(at + 1)
            val (h, p) = splitHostPort(right)
            try {
                val d = String(b64(dec(left)), Charsets.UTF_8)
                val ci = d.indexOf(':')
                if (ci > 0) {
                    build(d.substring(0, ci), d.substring(ci + 1), h, p)?.let { return it }
                }
            } catch (_: Exception) { /* قد يكون نصًا صريحًا */ }

            val ci = left.indexOf(':')
            if (ci > 0) {
                build(dec(left.substring(0, ci)), dec(left.substring(ci + 1)), h, p)?.let { return it }
            }
        }

        // 2) base64 لكامل النص: method:pass@host:port
        for (cand in listOf(body, dec(body))) {
            try {
                val d = String(b64(cand), Charsets.UTF_8)
                plain(d)?.let { (m, pass, hp) ->
                    val (h, p) = splitHostPort(hp)
                    build(m, pass, h, p)?.let { return it }
                }
            } catch (_: Exception) { }
        }
        return null
    }

    // ───────────────────────── hysteria2 ─────────────────────────
    private fun parseQueryString(query: String): Map<String, String> {
        if (query.isBlank()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        query.split("&").forEach { pair ->
            if (pair.isNotBlank()) {
                val k = dec(pair.substringBefore("="))
                val v = dec(pair.substringAfter("=", ""))
                if (k.isNotBlank() && !out.containsKey(k)) out[k] = v
            }
        }
        return out
    }

    private fun hysteria2(cfg: String): JSONObject? {
        val rest = cfg.substringAfter("://", "")
        if (rest.isBlank()) return null

        val hier = rest.substringBefore("?")
        val queryStr = rest.substringAfter("?", "")
        val authority = hier.substringBefore("/")
        val userInfo = if (authority.contains('@')) authority.substringBeforeLast('@') else ""
        val hostPort = if (authority.contains('@')) authority.substringAfterLast('@') else authority

        val host: String
        val portSpec: String
        if (hostPort.startsWith("[")) {
            val close = hostPort.indexOf(']')
            if (close <= 1) return null
            host = hostPort.substring(1, close).trim()
            portSpec = hostPort.substring(close + 1).removePrefix(":")
        } else if (hostPort.contains(':')) {
            host = hostPort.substringBeforeLast(':').trim()
            portSpec = hostPort.substringAfterLast(':').trim()
        } else {
            host = hostPort.trim()
            portSpec = ""
        }
        if (host.isBlank()) return null

        val q = parseQueryString(queryStr)
        val combinedPorts = listOf(portSpec, q["mport"] ?: "")
            .filter { it.isNotBlank() }
            .joinToString(",")
        val tokens = if (combinedPorts.isBlank()) listOf("443")
        else combinedPorts.split(",").map { it.trim() }.filter { it.isNotBlank() }

        val hasHopping = tokens.size > 1 || tokens.any { it.contains('-') || it.contains(':') }

        val ob = JSONObject()
            .put("type", "hysteria2")
            .put("server", host)
            .put("password", dec(userInfo))
            .put("tls", tlsBlock(host, q, listOf("h3")))

        if (hasHopping) {
            val ranges = ArrayList<String>()
            for (tok in tokens) {
                val sep = when {
                    tok.contains('-') -> '-'
                    tok.contains(':') -> ':'
                    else -> null
                }
                if (sep != null) {
                    val a = tok.substringBefore(sep).trim().toIntOrNull() ?: continue
                    val b = tok.substringAfter(sep).trim().toIntOrNull() ?: continue
                    if (validPort(a) && validPort(b) && a <= b) ranges.add("$a:$b")
                } else {
                    val p = tok.toIntOrNull() ?: continue
                    if (validPort(p)) ranges.add("$p:$p")
                }
            }
            if (ranges.isEmpty()) return null
            ob.put("server_ports", jsonArrayOfStrings(ranges))
        } else {
            val p = tokens.firstOrNull()?.toIntOrNull() ?: 443
            if (!validPort(p)) return null
            ob.put("server_port", p)
        }

        if (q["obfs"] == "salamander" && !q["obfs-password"].isNullOrBlank()) {
            ob.put("obfs", JSONObject().put("type", "salamander")
                .put("password", q["obfs-password"]))
        }
        q["up"]?.toDoubleOrNull()?.toInt()?.takeIf { it > 0 }?.let { ob.put("up_mbps", it) }
        q["down"]?.toDoubleOrNull()?.toInt()?.takeIf { it > 0 }?.let { ob.put("down_mbps", it) }
        return ob
    }

    // ───────────────────────── tuic ─────────────────────────
    private fun tuic(cfg: String): JSONObject? {
        val u = Uri.parse(cfg)
        val q = q(u)
        val host = stripBrackets(u.host)
        val port = u.port.takeIf { it > 0 } ?: 443
        val rawUser = u.encodedUserInfo ?: ""
        val uuid = dec(rawUser.substringBefore(":")).trim()
        if (host.isBlank() || uuid.isBlank() || !validPort(port)) return null

        return JSONObject()
            .put("type", "tuic")
            .put("server", host)
            .put("server_port", port)
            .put("uuid", uuid)
            .put("password", dec(rawUser.substringAfter(":", "")))
            .put("congestion_control", q["congestion_control"]?.ifBlank { "bbr" } ?: "bbr")
            .put("udp_relay_mode", q["udp_relay_mode"]?.ifBlank { "native" } ?: "native")
            .put("tls", tlsBlock(host, q, listOf("h3")))
    }

    /** استخراج اسم المضيف لتنويع النتائج (مع كاش سريع). */
    fun hostOf(cfg: String): String = metaOf(cfg).host

    /** اسم مختصر للعرض (المضيف:المنفذ) مع كاش سريع. */
    fun endpointLabel(cfg: String): String = metaOf(cfg).endpoint

    /** شارة البروتوكول المختصرة للعرض في الواجهة. */
    fun protocolBadge(cfg: String): String = when (schemeOf(cfg)) {
        "hysteria2", "hy2" -> "HY2"
        "vless" -> "VLESS"
        "vmess" -> "VMESS"
        "trojan" -> "TROJAN"
        "ss" -> "SS"
        "tuic" -> "TUIC"
        else -> schemeOf(cfg).uppercase().ifBlank { "VPN" }
    }

    /**
     * تسمية الكانفيغ باسم موحّد (مثل "bahrain-vpn 1 | 45ms") مع مراعاة بنية كل بروتوكول:
     * - vmess:// يتم تحديث حقل "ps" داخل JSON المرمّز بـ Base64 بدون إضافة #fragment خارجي.
     * - بقية البروتوكولات يتم إلحاق #{label} بعد إزالة أي وسم سابق.
     */
    fun namedUri(cfg: String, label: String): String {
        val cleaned = cleanUri(cfg)
        if (schemeOf(cleaned) == "vmess") {
            return try {
                val payload = cleaned.removePrefix("vmess://").substringBefore("?")
                val j = JSONObject(String(b64(payload), Charsets.UTF_8))
                j.put("ps", label)
                val enc = Base64.encodeToString(
                    j.toString().toByteArray(Charsets.UTF_8),
                    Base64.NO_WRAP,
                )
                "vmess://$enc"
            } catch (_: Exception) {
                cleaned
            }
        }
        return "$cleaned#$label"
    }

    /** قراءة الوسم النصي (remark / ps) من رابط الكانفيغ إن وُجد. */
    fun extractRemark(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.lowercase().startsWith("vmess://") && !trimmed.contains("#")) {
            return try {
                val payload = cleanUri(trimmed).removePrefix("vmess://").substringBefore("?")
                val j = JSONObject(String(b64(payload), Charsets.UTF_8))
                j.optString("ps", "")
            } catch (_: Exception) {
                ""
            }
        }
        return dec(trimmed.substringAfter("#", "")).trim()
    }
}
