package com.bahrain.vpnconfigs.data

import com.bahrain.vpnconfigs.BuildConfig
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Verifies top500.manifest.json against its detached ECDSA P-256 / SHA-256 signature
 * (`top500.manifest.json.sig`, base64 DER) produced by central_top500.sign_manifest_file.
 *
 * When no public key is compiled in (BuildConfig.TOP500_PUBLIC_KEY_B64 empty) the app runs in
 * transition mode and accepts unsigned manifests, so existing deployments keep working.
 * Once a key is configured, a missing or invalid signature is always rejected.
 */
object ManifestSignature {

    fun isTrusted(
        manifestBody: String,
        publicKeyB64: String = BuildConfig.TOP500_PUBLIC_KEY_B64,
        fetchSignature: () -> String?,
    ): Boolean {
        if (publicKeyB64.isBlank()) return true
        val sig = fetchSignature()?.trim().orEmpty()
        if (sig.isEmpty()) return false
        return verify(manifestBody.toByteArray(Charsets.UTF_8), sig, publicKeyB64)
    }

    fun verify(data: ByteArray, signatureB64: String, publicKeyB64: String): Boolean = runCatching {
        val key: PublicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyB64.trim())))
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(data)
            verify(Base64.getDecoder().decode(signatureB64.trim()))
        }
    }.getOrDefault(false)
}
