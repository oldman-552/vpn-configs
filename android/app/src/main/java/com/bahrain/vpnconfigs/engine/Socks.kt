// =====================================================================
// Socks.kt — طلب HTTP عبر socks5h محلي (بدون مكتبات خارجية).
// يستخدمه المُختبِر لطلب generate_204 عبر النفق وقياس الزمن/السرعة.
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
)

object Socks {

    /**
     * GET عبر socks5h (تحليل الاسم عند البروكسي) على 127.0.0.1:[proxyPort].
     * يغلق المقابس في جميع الحالات ولا يعلّق بانتظار جسم لردود 204/304 أو Content-Length: 0.
     */
    fun get(
        proxyPort: Int,
        url: String,
        timeoutMs: Int,
        maxBytes: Long = 0,
    ): HttpProbe {
        val uri = java.net.URI(url)
        val host = uri.host ?: throw IllegalArgumentException("Invalid URL host: $url")
        val isHttps = uri.scheme.equals("https", true)
        val port = if (uri.port > 0) uri.port else if (isHttps) 443 else 80
        val path = (uri.rawPath.ifBlank { "/" }) + (uri.rawQuery?.let { "?$it" } ?: "")

        val started = System.nanoTime()
        val raw = Socket()
        var sslSock: Socket? = null

        try {
            raw.soTimeout = timeoutMs
            raw.connect(InetSocketAddress("127.0.0.1", proxyPort), timeoutMs)

            // ── مصافحة socks5 مباشرة على التدفق الخام دون تخزين مؤقت يبتلع بيانات TLS ──
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
                    soTimeout = timeoutMs
                    sslParameters = sslParameters.apply {
                        endpointIdentificationAlgorithm = "HTTPS"
                    }
                    startHandshake()
                }.also { sslSock = it }
            } else {
                raw
            }

            val request = buildString {
                append("GET ").append(path).append(" HTTP/1.1\r\n")
                append("Host: ").append(host).append("\r\n")
                append("User-Agent: BahrainConfigs/1.1\r\n")
                append("Accept: */*\r\n")
                append("Connection: close\r\n\r\n")
            }
            activeSock.getOutputStream().apply {
                write(request.toByteArray(Charsets.US_ASCII))
                flush()
            }

            val input = BufferedInputStream(activeSock.getInputStream())
            val statusLine = readLine(input)
            val status = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0

            var contentLength: Long? = null
            while (true) {
                val line = readLine(input)
                if (line.isEmpty()) break
                if (line.startsWith("Content-Length:", true)) {
                    contentLength = line.substringAfter(":").trim().toLongOrNull()
                }
            }

            val noBody = status == 204 || status == 304 || status in 100..199 || contentLength == 0L
            if (noBody) {
                val elapsed = (System.nanoTime() - started) / 1_000_000
                return HttpProbe(status, elapsed, 0L)
            }

            val limit = when {
                contentLength != null && contentLength > 0L ->
                    if (maxBytes > 0L) minOf(maxBytes, contentLength) else contentLength
                maxBytes > 0L -> maxBytes
                else -> 64L * 1024L
            }

            val buf = ByteArray(16 * 1024)
            var read = 0L
            while (read < limit) {
                val n = input.read(buf, 0, minOf(buf.size.toLong(), limit - read).toInt())
                if (n <= 0) break
                read += n
            }

            val elapsed = (System.nanoTime() - started) / 1_000_000
            return HttpProbe(status, elapsed, read)
        } finally {
            try { sslSock?.close() } catch (_: Exception) { }
            try { raw.close() } catch (_: Exception) { }
        }
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
