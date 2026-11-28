/**
 * crypto_github.js — Real WebCrypto + GitHub Serverless Engine for ULTIMATE VPN ENTERPRISE.
 * Byte-compatible with Python `enterprise/crypto_security.py` and Android `EnterpriseCrypto`.
 * Zero embedded secrets or tokens: credentials reside only in administrator session memory.
 */

const EnterpriseWebCrypto = (() => {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PBKDF2_ITER = 120000;
  const LOOKUP_DOMAIN = "bahrain-vpn-enterprise-v3-user-lookup";
  const VIP_NODES_AAD = "bahrain-vpn-vip-nodes-v31";

  function bytesToB64(bytes) {
    let bin = "";
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
    return btoa(bin);
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(new Uint8Array(bytes))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function hexToBytes(hex) {
    const clean = hex.trim();
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function randomHex(byteLen = 16) {
    const b = new Uint8Array(byteLen);
    crypto.getRandomValues(b);
    return bytesToHex(b);
  }

  function canonicalJson(val) {
    if (val === null || val === undefined) return "null";
    if (typeof val === "boolean") return val ? "true" : "false";
    if (typeof val === "number") return Number.isFinite(val) ? String(val) : "0";
    if (typeof val === "string") return JSON.stringify(val);
    if (Array.isArray(val)) return "[" + val.map(canonicalJson).join(",") + "]";
    const keys = Object.keys(val).sort();
    return (
      "{" +
      keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(val[k])).join(",") +
      "}"
    );
  }

  async function sha256Hex(text) {
    const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
    return bytesToHex(digest);
  }

  async function computeUserLookupId(username) {
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(LOOKUP_DOMAIN),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign(
      "HMAC",
      key,
      enc.encode(username.trim().toLowerCase())
    );
    return bytesToHex(sig);
  }

  async function derivePbkdf2AesKey(secret, saltBytes, usages = ["encrypt", "decrypt"]) {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITER, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      usages
    );
  }

  async function encryptAesGcm(secret, saltHex, plainText, aadStr = "") {
    const key = await derivePbkdf2AesKey(secret, hexToBytes(saltHex), ["encrypt"]);
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const params = { name: "AES-GCM", iv };
    if (aadStr) params.additionalData = enc.encode(aadStr);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(params, key, enc.encode(plainText))
    );
    const merged = new Uint8Array(12 + ct.length);
    merged.set(iv, 0);
    merged.set(ct, 12);
    return bytesToB64(merged);
  }

  async function decryptAesGcm(secret, saltHex, tokenB64, aadStr = "") {
    const raw = b64ToBytes(tokenB64);
    const iv = raw.slice(0, 12);
    const ct = raw.slice(12);
    const key = await derivePbkdf2AesKey(secret, hexToBytes(saltHex), ["decrypt"]);
    const params = { name: "AES-GCM", iv };
    if (aadStr) params.additionalData = enc.encode(aadStr);
    const plain = await crypto.subtle.decrypt(params, key, ct);
    return dec.decode(plain);
  }

  async function sealUserLicenseEnvelope(username, password, saltHex, envelopeObj) {
    const norm = username.trim().toLowerCase();
    const jsonStr = canonicalJson(envelopeObj);
    return encryptAesGcm(`${norm}:${password}`, saltHex, jsonStr, norm);
  }

  async function encryptRawKeyAesGcm(keyHex, plainText, aadStr = VIP_NODES_AAD) {
    const rawKey = hexToBytes(keyHex);
    const key = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const params = { name: "AES-GCM", iv };
    if (aadStr) params.additionalData = enc.encode(aadStr);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(params, key, enc.encode(plainText))
    );
    const merged = new Uint8Array(12 + ct.length);
    merged.set(iv, 0);
    merged.set(ct, 12);
    return bytesToB64(merged);
  }

  async function decryptRawKeyAesGcm(keyHex, tokenB64, aadStr = VIP_NODES_AAD) {
    const raw = b64ToBytes(tokenB64);
    const iv = raw.slice(0, 12);
    const ct = raw.slice(12);
    const key = await crypto.subtle.importKey(
      "raw",
      hexToBytes(keyHex),
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    const params = { name: "AES-GCM", iv };
    if (aadStr) params.additionalData = enc.encode(aadStr);
    const plain = await crypto.subtle.decrypt(params, key, ct);
    return dec.decode(plain);
  }

  async function generateEcdsaP256KeyPair() {
    const kp = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const privPkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);
    const pubSpki = await crypto.subtle.exportKey("spki", kp.publicKey);
    return {
      privatePkcs8B64: bytesToB64(privPkcs8),
      publicSpkiB64: bytesToB64(pubSpki),
    };
  }

  async function signEcdsaP1363B64(privatePkcs8B64, canonicalBytesStr) {
    const priv = await crypto.subtle.importKey(
      "pkcs8",
      b64ToBytes(privatePkcs8B64),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
    // WebCrypto ECDSA produces 64-byte IEEE P1363 signature, accepted directly by Android & Python!
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      priv,
      enc.encode(canonicalBytesStr)
    );
    return bytesToB64(sig);
  }

  // RFC 6238 TOTP (Base32 + HMAC-SHA1)
  const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  function generateTotpSecretB32() {
    const rnd = new Uint8Array(20);
    crypto.getRandomValues(rnd);
    let bits = 0, value = 0, out = "";
    for (let i = 0; i < rnd.length; i++) {
      value = (value << 8) | rnd[i];
      bits += 8;
      while (bits >= 5) {
        out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    return out;
  }

  function decodeBase32(str) {
    const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, "");
    let bits = 0, value = 0;
    const out = [];
    for (let i = 0; i < clean.length; i++) {
      value = (value << 5) | B32_ALPHABET.indexOf(clean[i]);
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }

  async function computeTotpCode(secretB32, unixSec = Math.floor(Date.now() / 1000)) {
    const keyBytes = decodeBase32(secretB32);
    const counter = Math.floor(unixSec / 30);
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setUint32(0, Math.floor(counter / 0x100000000), false);
    view.setUint32(4, counter >>> 0, false);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-1" },
      false,
      ["sign"]
    );
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, buf));
    const offset = mac[mac.length - 1] & 0x0f;
    const bin =
      (((mac[offset] & 0x7f) << 24) |
        ((mac[offset + 1] & 0xff) << 16) |
        ((mac[offset + 2] & 0xff) << 8) |
        (mac[offset + 3] & 0xff)) >>>
      0;
    return String(bin % 1000000).padStart(6, "0");
  }

  async function verifyTotp(secretB32, code) {
    if (!secretB32) return true;
    const clean = String(code || "").trim();
    if (!/^\d{6}$/.test(clean)) return false;
    const now = Math.floor(Date.now() / 1000);
    for (const d of [-30, 0, 30]) {
      if ((await computeTotpCode(secretB32, now + d)) === clean) return true;
    }
    return false;
  }

  return {
    VIP_NODES_AAD,
    randomHex,
    canonicalJson,
    sha256Hex,
    computeUserLookupId,
    encryptAesGcm,
    decryptAesGcm,
    encryptRawKeyAesGcm,
    decryptRawKeyAesGcm,
    sealUserLicenseEnvelope,
    generateEcdsaP256KeyPair,
    signEcdsaP1363B64,
    generateTotpSecretB32,
    computeTotpCode,
    verifyTotp,
  };
})();

const GitHubServerlessApi = (() => {
  async function ghFetch(repoFull, token, path, options = {}) {
    const headers = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers || {}),
    };
    if (token) headers.Authorization = `Bearer ${token}`;
    const resp = await fetch(`https://api.github.com/repos/${repoFull}${path}`, {
      ...options,
      headers,
    });
    return resp;
  }

  async function readBranchJson(repoFull, token, branch, filePath) {
    const resp = await ghFetch(
      repoFull,
      token,
      `/contents/${filePath}?ref=${encodeURIComponent(branch)}`
    );
    if (resp.status === 404) return { exists: false, sha: null, data: null };
    if (!resp.ok) throw new Error(`GitHub API ${resp.status} reading ${filePath}`);
    const meta = await resp.json();
    const rawStr = new TextDecoder().decode(
      Uint8Array.from(atob((meta.content || "").replace(/\s+/g, "")), (c) =>
        c.charCodeAt(0)
      )
    );
    return { exists: true, sha: meta.sha, data: JSON.parse(rawStr) };
  }

  async function writeBranchJson(repoFull, token, branch, filePath, obj, prevSha, message) {
    const utf8Bytes = new TextEncoder().encode(JSON.stringify(obj, null, 2));
    let bin = "";
    for (let i = 0; i < utf8Bytes.length; i++) bin += String.fromCharCode(utf8Bytes[i]);
    const body = {
      message,
      content: btoa(bin),
      branch,
    };
    if (prevSha) body.sha = prevSha;
    const resp = await ghFetch(repoFull, token, `/contents/${filePath}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const errTxt = await resp.text();
      throw new Error(`GitHub PUT ${resp.status}: ${errTxt.slice(0, 180)}`);
    }
    return resp.json();
  }

  async function triggerWorkflow(repoFull, token, workflowFile, ref = "main", inputs = {}) {
    const resp = await ghFetch(
      repoFull,
      token,
      `/actions/workflows/${workflowFile}/dispatches`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ref, inputs }),
      }
    );
    if (!resp.ok && resp.status !== 204) {
      throw new Error(`Workflow dispatch failed: HTTP ${resp.status}`);
    }
    return true;
  }

  return { readBranchJson, writeBranchJson, triggerWorkflow };
})();
