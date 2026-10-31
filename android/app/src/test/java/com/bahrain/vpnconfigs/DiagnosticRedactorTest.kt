package com.bahrain.vpnconfigs

import com.bahrain.vpnconfigs.util.DiagnosticRedactor
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticRedactorTest {
    @Test fun masksCredentialsHostsAndIps() {
        val out = DiagnosticRedactor.clean(
            "switch to vless://1111-2222@srv.example.com:443?pbk=abc#x exit 203.0.113.77 v6 2001:db8:85a3::8a2e:370:7334",
        )
        assertFalse(out.contains("1111-2222"))
        assertFalse(out.contains("srv.example.com"))
        assertFalse(out.contains("113.77"))
        assertFalse(out.contains("2001:db8"))
        assertTrue(out.contains("203.0.x.x"))
    }

    @Test fun blankIsEmpty() = assertTrue(DiagnosticRedactor.clean(null).isEmpty())
}
