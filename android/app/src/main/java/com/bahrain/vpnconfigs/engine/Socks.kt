// =====================================================================
// Socks.kt — طلب HTTP عبر socks5h محلي + قياس Real Delay (Current) الدقيق.
// يفصل زمن تأسيس الجلسة الأولى (DNS + TCP + TLS) عن زمن الاستجابة الفعلي
// للنفق المفتوح (Real Delay) تمامًا كما في v2rayNG / Clash Unified Delay.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

data class HttpProbe(
    val status: Int,
    val elapsedMs: Long,
    val bytes: Long,
    val bodyText: String = "",
    val transferMs: Long = elapsedMs,
    val establishMs: Long = 0L,
    val jitterMs: Double = 0.0,
)

object Socks {

    private fun openTunnelSocket(
        proxyPort: Int,
        host: String,
        port: Int,
        isHttps: Boolean,
        timeoutMs: Int,
    ): Pair<Socket, Socket> {
        val raw = Socket()
        try {
            raw.tcpNoDelay = true
            raw.soTimeout = timeoutMs
            raw.connect(InetSocketAddress("127.0.0.1", proxyPort), timeoutMs)

            val rawOut = raw.getOutputStream()
            val rawIn = raw.getInputStream()

            rawOut.write(byteArrayOf(0x05, 0x01, 0x00))
            rawOut.flush()

            val resp = ByteArray(2)
            readFully(rawIn, resp)
            require(resp[0].toInt() == 0x05 && resp[1].toInt() == 0x00) { "socks5 auth rejected" }

            val hostBytes = host.toByteArray(Charsets.US_ASCII)
            require(hostBytes.size in 1..255) { "invalid host length" }
            val connect = ByteArrayOutputStream().apply {
                write(byteArrayOf(0x05, 0x01, 0x00, 0x03, hostBytes.size.toByte()))
                write(hostBytes)
                write(byteArrayOf((port shr 8).toByte(), (port and 0xFF).toByte()))
            }.toByteArray()
            rawOut.write(connect)
            rawOut.flush()

            val head = ByteArray(4)
            readFully(rawIn, head)
            require((head[1].toInt() and 0xFF) == 0x00) { "socks5 connect failed: ${head[1]}" }
            when (head[3].toInt() and 0xFF) {
                0x01 -> skipFully(rawIn, 4 + 2)
                0x04 -> skipFully(rawIn, 16 + 2)
                0x03 -> {
                    val n = rawIn.read()
                    if (n < 0) throw EOFException("socks domain length EOF")
                    skipFully(rawIn, n + 2)
                }
                else -> throw IllegalStateException("unknown socks5 atyp: ${head[3]}")
            }

            val activeSock: Socket = if (isHttps) {
                val f = SSLSocketFactory.getDefault() as SSLSocketFactory
                (f.createSocket(raw, host, port, true) as SSLSocket).apply {
                    tcpNoDelay = true
                    soTimeout = timeoutMs
                    sslParameters = sslParameters.apply {
                        endpointIdentificationAlgorithm = "HTTPS"
                    }
                    startHandshake()
                }
            } else {
                raw
            }
            return raw to activeSock
        } catch (e: Exception) {
            runCatching { raw.close() }
            throw e
        }
    }

    /**
     * قياس Real Delay (Current) الحقيقي مثل v2rayNG / Hiddify:
     * 1) يؤسس النفق ومصافحة TLS كاملةً أولًا (للتأكد أن السيرفر شغّال فعليًا ويمرر HTTPS).
     * 2) يقيس زمن ذهاب وعودة طلب HTTP generate_204 الصافي عبر النفق الدافئ (Keep-Alive)
     *    بحيث لا يتضخّم الرقم بزمن DNS ومصافحات التأسيس الباردة.
     */
    fun measureRealDelay(
        proxyPort: Int,
        url: String = SingBox.TEST_URL,
        timeoutMs: Int = 5000,
    ): HttpProbe {
        val uri = java.net.URI(url)
        val host = uri.host ?: throw IllegalArgumentException("Invalid URL host: $url")
        val isHttps = uri.scheme.equals("https", true)
        val port = if (uri.port > 0) uri.port else if (isHttps) 443 else 80
        val path = (uri.rawPath.ifBlank { "/" }) + (uri.rawQuery?.let { "?$it" } ?: "")

        var raw: Socket? = null
        var activeSock: Socket? = null
        val connectStartNs = System.nanoTime()
        try {
            val pair = openTunnelSocket(proxyPort, host, port, isHttps, timeoutMs)
            val estabMs = ((System.nanoTime() - connectStartNs) / 1_000_000L).coerceAtLeast(1L)
            raw = pair.first
            activeSock = pair.second

            val out = activeSock.getOutputStream()
            val input = BufferedInputStream(activeSock.getInputStream())

            // النبضة 1: بعد انتهاء مصافحة TLS، نقيس أول رحلة HTTP فعلية ونبقي الجلسة دافئة
            val req1 = buildString {
                append("GET ").append(path).append(" HTTP/1.1\r\n")
                append("Host: ").append(host).append("\r\n")
                append("User-Agent: bahrain-vpn/2.2\r\n")
                append("Accept: */*\r\n")
                append("Connection: keep-alive\r\n\r\n")
            }.toByteArray(Charsets.US_ASCII)

            val t1 = System.nanoTime()
            out.write(req1)
            out.flush()

            val (status1, contentLen1, connClose1) = readResponseHeaders(input)
            if (status1 !in listOf(200, 204)) {
                return HttpProbe(status1, 0L, 0L, establishMs = estabMs)
            }
            if (status1 != 204 && contentLen1 != null && contentLen1 > 0L) {
                skipFully(input, minOf(contentLen1, 4096L).toInt())
            }
            val rtt1 = ((System.nanoTime() - t1) / 1_000_000L).coerceAtLeast(1L)

            // النبضة 2 (Keep-Alive Warm Delay): قياس RTT النفق الصافي والتذبذب بدون أي عبء تأسيس إضافي
            var bestRtt = rtt1
            var measuredJitter = 0.0
            if (!connClose1 && (status1 == 204 || contentLen1 != null)) {
                runCatching {
                    activeSock.soTimeout = minOf(timeoutMs, 2200)
                    val req2 = buildString {
                        append("GET ").append(path).append(" HTTP/1.1\r\n")
                        append("Host: ").append(host).append("\r\n")
                        append("User-Agent: bahrain-vpn/2.2\r\n")
                        append("Accept: */*\r\n")
                        append("Connection: close\r\n\r\n")
                    }.toByteArray(Charsets.US_ASCII)
                    val t2 = System.nanoTime()
                    out.write(req2)
                    out.flush()
                    val (status2, _, _) = readResponseHeaders(input)
                    if (status2 in listOf(200, 204)) {
                        val rtt2 = ((System.nanoTime() - t2) / 1_000_000L).coerceAtLeast(1L)
                        bestRtt = minOf(rtt1, rtt2)
                        measuredJitter = kotlin.math.abs(rtt1 - rtt2).toDouble()
                    }
                }
            }

            return HttpProbe(
                status = status1,
                elapsedMs = bestRtt,
                bytes = 0L,
                transferMs = bestRtt,
                establishMs = estabMs,
                jitterMs = measuredJitter,
            )
        } finally {
            runCatching { if (activeSock !== raw) activeSock?.close() }
            runCatching { raw?.close() }
        }
    }

    /**
     * GET عبر socks5h على 127.0.0.1:[proxyPort] لتحميل البيانات (قياس السرعة أو trace).
     * يحسب transferMs بدقة من لحظة إرسال طلب HTTP بعد اكتمال مصافحة TLS.
     */
    fun get(
        proxyPort: Int,
        url: String,
        timeoutMs: Int,
        maxBytes: Long = 0,
        captureText: Boolean = false,
    ): HttpProbe {
        val uri = java.net.URI(url)
        val host = uri.host ?: throw IllegalArgumentException("Invalid URL host: $url")
        val isHttps = uri.scheme.equals("https", true)
        val port = if (uri.port > 0) uri.port else if (isHttps) 443 else 80
        val path = (uri.rawPath.ifBlank { "/" }) + (uri.rawQuery?.let { "?$it" } ?: "")

        val started = System.nanoTime()
        var raw: Socket? = null
        var activeSock: Socket? = null

        try {
            val pair = openTunnelSocket(proxyPort, host, port, isHttps, timeoutMs)
            raw = pair.first
            activeSock = pair.second

            val request = buildString {
                append("GET ").append(path).append(" HTTP/1.1\r\n")
                append("Host: ").append(host).append("\r\n")
                append("User-Agent: bahrain-vpn/2.2\r\n")
                append("Accept: */*\r\n")
                append("Connection: close\r\n\r\n")
            }

            val transferStarted = System.nanoTime()
            activeSock.getOutputStream().apply {
                write(request.toByteArray(Charsets.US_ASCII))
                flush()
            }

            val input = BufferedInputStream(activeSock.getInputStream())
            val (status, contentLength, _) = readResponseHeaders(input)

            val noBody = status == 204 || status == 304 || status in 100..199 || contentLength == 0L
            if (noBody) {
                val transferElapsed = ((System.nanoTime() - transferStarted) / 1_000_000L).coerceAtLeast(1L)
                val totalElapsed = ((System.nanoTime() - started) / 1_000_000L).coerceAtLeast(1L)
                return HttpProbe(status, totalElapsed, 0L, transferMs = transferElapsed)
            }

            val limit = when {
                contentLength != null && contentLength > 0L ->
                    if (maxBytes > 0L) minOf(maxBytes, contentLength) else contentLength
                maxBytes > 0L -> maxBytes
                else -> 64L * 1024L
            }

            val firstByteStarted = System.nanoTime()
            val buf = ByteArray(16 * 1024)
            val captured = if (captureText) ByteArrayOutputStream() else null
            var read = 0L
            while (read < limit) {
                val n = input.read(buf, 0, minOf(buf.size.toLong(), limit - read).toInt())
                if (n <= 0) break
                if (captured != null && captured.size() < 8192) {
                    captured.write(buf, 0, minOf(n, 8192 - captured.size()))
                }
                read += n
            }

            val totalElapsed = ((System.nanoTime() - started) / 1_000_000L).coerceAtLeast(1L)
            val bodyTransferMs = ((System.nanoTime() - firstByteStarted) / 1_000_000L)
                .let { if (it >= 15L) it else ((System.nanoTime() - transferStarted) / 1_000_000L).coerceAtLeast(1L) }
            val text = captured?.toString(Charsets.UTF_8.name()) ?: ""
            return HttpProbe(status, totalElapsed, read, text, transferMs = bodyTransferMs)
        } finally {
            runCatching { if (activeSock !== raw) activeSock?.close() }
            runCatching { raw?.close() }
        }
    }

    private fun readResponseHeaders(input: BufferedInputStream): Triple<Int, Long?, Boolean> {
        val statusLine = readLine(input)
        val status = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0
        var contentLength: Long? = null
        var connClose = false
        while (true) {
            val line = readLine(input)
            if (line.isEmpty()) break
            if (line.startsWith("Content-Length:", true)) {
                contentLength = line.substringAfter(":").trim().toLongOrNull()
            } else if (line.startsWith("Connection:", true)) {
                connClose = line.substringAfter(":").contains("close", ignoreCase = true)
            }
        }
        return Triple(status, contentLength, connClose)
    }

    private fun readFully(input: InputStream, dst: ByteArray) {
        var off = 0
        while (off < dst.size) {
            val n = input.read(dst, off, dst.size - off)
            if (n < 0) throw EOFException("socks closed")
            off += n
        }
    }

    private fun skipFully(input: InputStream, count: Int) {
        val scratch = ByteArray(minOf(maxOf(count, 1), 260))
        var left = count
        while (left > 0) {
            val n = input.read(scratch, 0, minOf(left, scratch.size))
            if (n < 0) throw EOFException("socks skip EOF")
            left -= n
        }
    }

    private fun readLine(input: BufferedInputStream): String {
        val sb = StringBuilder()
        while (true) {
            val c = input.read()
            if (c < 0) break
            if (c == '\n'.code) break
            if (c != '\r'.code) sb.append(c.toChar())
            if (sb.length > 8 * 1024) break
        }
        return sb.toString()
    }
}
