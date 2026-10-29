// =====================================================================
// Socks.kt — طلب HTTP عبر socks5h محلي (بدون مكتبات خارجية).
// يستخدمه المُختبِر لطلب generate_204 عبر النفق وقياس الزمن/السرعة.
// =====================================================================
package com.bahrain.vpnconfigs.engine

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocketFactory

data class HttpProbe(
    val status: Int,
    val elapsedMs: Long,
    val bytes: Long,
)

object Socks {

    /**
     * GET عبر socks5h (تحليل الاسم عند البروكسي) على 127.0.0.1:[proxyPort].
     * @param maxBytes 0 = حتى نهاية الجسم (بسقف أمان).
     */
    fun get(
        proxyPort: Int,
        url: String,
        timeoutMs: Int,
        maxBytes: Long = 0,
    ): HttpProbe {
        val uri = java.net.URI(url)
        val host = uri.host
        val isHttps = uri.scheme.equals("https", true)
        val port = if (uri.port > 0) uri.port else if (isHttps) 443 else 80
        val path = (uri.rawPath.ifBlank { "/" }) + (uri.rawQuery?.let { "?$it" } ?: "")

        val started = System.nanoTime()

        // ── مصافحة socks5 ──
        val raw = Socket()
        raw.soTimeout = timeoutMs
        raw.connect(InetSocketAddress("127.0.0.1", proxyPort), timeoutMs)

        raw.getOutputStream().apply {
            write(byteArrayOf(0x05, 0x01, 0x00))       // v5, طريقة واحدة: بلا مصادقة
            flush()
        }
        val inS = BufferedInputStream(raw.getInputStream())
        val resp = ByteArray(2)
        readFully(inS, resp)
        require(resp[0].toInt() == 0x05 && resp[1].toInt() == 0x00) { "socks5 auth rejected" }

        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val connect = ByteArrayOutputStream().apply {
            write(byteArrayOf(0x05, 0x01, 0x00, 0x03, hostBytes.size.toByte()))
            write(hostBytes)                            // اسم النطاق (rdns)
            write(byteArrayOf((port shr 8).toByte(), (port and 0xFF).toByte()))
        }.toByteArray()
        raw.getOutputStream().apply { write(connect); flush() }

        val head = ByteArray(4)
        readFully(inS, head)
        require(head[1].toInt() == 0x00) { "socks5 connect failed: ${head[1]}" }
        when (head[3].toInt()) {                        // تخطّي عنوان الردّ
            0x01 -> skip(inS, 4 + 2)
            0x04 -> skip(inS, 16 + 2)
            0x03 -> { val n = inS.read(); skip(inS, n + 2) }
        }

        val sock: Socket = if (isHttps) {
            val f = SSLSocketFactory.getDefault() as SSLSocketFactory
            (f.createSocket(raw, host, port, true) as javax.net.ssl.SSLSocket).apply {
                soTimeout = timeoutMs
                startHandshake()
            }
        } else raw

        val request = buildString {
            append("GET ").append(path).append(" HTTP/1.1\r\n")
            append("Host: ").append(host).append("\r\n")
            append("User-Agent: BahrainConfigs/1.0\r\n")
            append("Accept: */*\r\n")
            append("Connection: close\r\n\r\n")
        }
        sock.getOutputStream().apply { write(request.toByteArray()); flush() }

        val input = BufferedInputStream(sock.getInputStream())
        val statusLine = readLine(input)
        val status = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 0

        var contentLength = 0L
        while (true) {
            val line = readLine(input)
            if (line.isEmpty()) break
            if (line.startsWith("Content-Length:", true)) {
                contentLength = line.substringAfter(":").trim().toLongOrNull() ?: 0L
            }
        }

        val limit = when {
            maxBytes > 0 -> maxBytes
            contentLength > 0 -> contentLength
            else -> 64L * 1024
        }
        val buf = ByteArray(16 * 1024)
        var read = 0L
        try {
            while (read < limit) {
                val n = input.read(buf, 0, minOf(buf.size.toLong(), limit - read).toInt())
                if (n <= 0) break
                read += n
            }
        } finally {
            try { sock.close() } catch (_: Exception) { }
            try { raw.close() } catch (_: Exception) { }
        }

        val elapsed = (System.nanoTime() - started) / 1_000_000
        return HttpProbe(status, elapsed, read)
    }

    private fun readFully(input: BufferedInputStream, dst: ByteArray) {
        var off = 0
        while (off < dst.size) {
            val n = input.read(dst, off, dst.size - off)
            if (n < 0) throw java.io.EOFException("socks closed")
            off += n
        }
    }

    private fun skip(input: BufferedInputStream, n: Int) {
        var left = n
        while (left > 0) {
            val r = input.read(ByteArray(minOf(left, 512)))
            if (r < 0) throw java.io.EOFException()
            left -= r
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
