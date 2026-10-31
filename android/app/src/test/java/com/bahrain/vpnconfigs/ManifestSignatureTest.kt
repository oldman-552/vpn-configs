package com.bahrain.vpnconfigs

import com.bahrain.vpnconfigs.data.ManifestSignature
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class ManifestSignatureTest {
    private val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val pubB64 = Base64.getEncoder().encodeToString(pair.public.encoded)
    private val body = "{\"dataset_version\": 7}\n"
    private val sigB64 = Base64.getEncoder().encodeToString(
        Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(body.toByteArray()); sign() },
    )

    @Test fun validSignatureIsTrusted() = assertTrue(ManifestSignature.isTrusted(body, pubB64) { sigB64 })
    @Test fun tamperedManifestIsRejected() = assertFalse(ManifestSignature.isTrusted(body.replace("7", "8"), pubB64) { sigB64 })
    @Test fun missingSignatureIsRejectedWhenKeyConfigured() = assertFalse(ManifestSignature.isTrusted(body, pubB64) { null })
    @Test fun transitionModeAcceptsUnsigned() = assertTrue(ManifestSignature.isTrusted(body, "") { null })
}
