package com.bahrain.vpnconfigs.util

/**
 * Extra redaction for exported diagnostic reports, on top of AppDiag.redactSecrets:
 * masks IPv4/IPv6 addresses and hostnames that follow "@" so a shared report
 * cannot reveal which servers the user connected to or their exit IP.
 */
object DiagnosticRedactor {
    private val IPV4 = Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")
    private val IPV6 = Regex("\\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\\b")
    private val AT_HOST = Regex("@[A-Za-z0-9.-]+(:\\d+)?")

    fun clean(raw: String?): String {
        if (raw.isNullOrBlank()) return ""
        var s = AppDiag.redactSecrets(raw)
        s = AT_HOST.replace(s, "@[HOST]")
        s = IPV4.replace(s) { m -> m.value.substringBeforeLast('.').substringBeforeLast('.') + ".x.x" }
        s = IPV6.replace(s, "[IPv6]")
        return s
    }
}
