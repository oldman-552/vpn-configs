package com.bahrain.vpnadmin

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AdminAppUnitTest {

    @Test
    fun adminTotpVaultEncryptionSignedBundleAndAuditChainWorkEndToEnd() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val mgr = AdminGitHubVaultManager(ctx)

        // 1. TOTP 2FA verification
        val totpSecret = AdminCrypto.generateTotpSecretB32()
        val nowSec = 1_793_361_600L
        val code = AdminCrypto.computeTotpCode(totpSecret, nowSec)
        assertTrue(AdminCrypto.verifyTotpCode(totpSecret, code, nowSec))
        assertFalse(AdminCrypto.verifyTotpCode(totpSecret, "000000", nowSec))

        // 2. Local Keystore/AES credentials persistence
        mgr.saveEncryptedCredentials("oldman-552/vpn-configs", "ghp_test_session_only", "rootadmin")
        val loaded = mgr.loadEncryptedCredentials()
        assertEquals("oldman-552/vpn-configs", loaded?.first)
        assertEquals("rootadmin", loaded?.third)

        // 3. Vault creation, user license sealing, bundle signing, and SHA-256 audit chain
        val db = mgr.createEmptyVaultDb()
        val uObj = JSONObject()
            .put("id", "usr_001")
            .put("username", "salman")
            .put("account_status", "FREE_TRIAL")
            .put("subscription_type", "FREE_TRIAL")
            .put("device_limit", 1)
        mgr.sealUserEnvelope(db, uObj, "SalmanPass#2026")
        db.getJSONArray("users").put(uObj)
        mgr.appendAuditLog(db, "rootadmin", "USER_CREATE", "users", "usr_001", JSONObject().put("u", "salman"))
        mgr.appendAuditLog(db, "rootadmin", "REMOTE_CONFIG", "remote_config", "auth_require_account", JSONObject().put("v", true))

        assertTrue(mgr.verifyAuditChain(db))

        val signedBundle = mgr.buildSignedPublicBundle(db)
        assertFalse(signedBundle.toString().contains("SalmanPass#2026"))
        assertFalse(signedBundle.toString().contains("\"salman\""))
        assertTrue(signedBundle.optString("signature_b64").isNotBlank())

        // 4. AES-256-GCM vault round-trip
        val salt = AdminCrypto.randomHex(16)
        val encVault = AdminCrypto.encryptAesGcm("MasterPass!2026", salt, db.toString(), "bahrain-vpn-admin-vault-v3")
        val decVault = AdminCrypto.decryptAesGcm("MasterPass!2026", salt, encVault, "bahrain-vpn-admin-vault-v3")
        assertEquals(1, JSONObject(decVault).getJSONArray("users").length())
    }

    @Test
    fun auditChainDetectsAnyTampering() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val mgr = AdminGitHubVaultManager(ctx)
        val db = mgr.createEmptyVaultDb()
        mgr.appendAuditLog(db, "admin1", "USER_CREATE", "users", "u1", JSONObject())
        mgr.appendAuditLog(db, "admin1", "USER_BLOCK", "users", "u1", JSONObject())
        assertTrue(mgr.verifyAuditChain(db))

        db.getJSONArray("admin_audit_logs").getJSONObject(0).put("action", "FORGED_ACTION")
        assertFalse(mgr.verifyAuditChain(db))
    }

    @Test
    fun vipPrivateNodesAreEncryptedInPublicBundleAndRecoverableByKey() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val mgr = AdminGitHubVaultManager(ctx)
        val db = mgr.createEmptyVaultDb()

        val uObj = JSONObject()
            .put("id", "usr_vip_1")
            .put("username", "vipuser")
            .put("account_status", "ACTIVE")
            .put("subscription_type", "YEARLY")
            .put("device_limit", 1)
        mgr.sealUserEnvelope(db, uObj, "VipSecret#2026")
        db.getJSONArray("users").put(uObj)

        db.getJSONArray("vip_servers").put(
            JSONObject()
                .put("id", "vip_bh_01")
                .put("label", "VIP Bahrain Private")
                .put("country", "BH")
                .put("protocol", "VLESS")
                .put("uri", "vless://11223344-5566-7788-99aa-bbccddeeff00@bh-private.node.internal:443#VIP")
                .put("priority", 250)
                .put("enabled", true)
        )

        val pubBundle = mgr.buildSignedPublicBundle(db)
        val rawStr = pubBundle.toString()
        assertFalse(rawStr.contains("bh-private.node.internal"))
        assertFalse(rawStr.contains("11223344-5566-7788"))

        val bundleObj = pubBundle.getJSONObject("bundle")
        assertEquals("1.0", bundleObj.optString("bundle_release"))
        val vipEnc = bundleObj.getString("vip_nodes_enc_b64")
        assertTrue(vipEnc.isNotBlank())

        val decryptedJson = AdminCrypto.decryptRawKeyAesGcm(db.getString("vip_key_hex"), vipEnc)
        assertTrue(decryptedJson.contains("bh-private.node.internal"))
    }
}
