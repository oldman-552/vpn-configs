"""Production cryptographic primitives for Ultimate VPN Enterprise.

Provides:
- Argon2id password hashing & constant-time verification (never stores plaintext).
- PBKDF2-HMAC-SHA256 (120,000 iterations) + AES-256-GCM cross-platform envelopes
  (byte-compatible across Python, Android JCA, and Browser WebCrypto).
- ECDSA P-256 (SHA-256) signing & verification (ASN.1 DER + IEEE P1363 helpers).
- RFC 6238 TOTP (6-digit, 30s) Two-Factor Authentication for Administrators.
- AES-256-GCM encrypted SQLite database backups & verified restoration.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ARGON2_TIME_COST = 2
ARGON2_MEMORY_KIB = 65536
ARGON2_LANES = 2
PBKDF2_ITERATIONS = 120_000
USERNAME_LOOKUP_DOMAIN = b"bahrain-vpn-enterprise-v3-user-lookup"
VIP_NODES_AAD = b"bahrain-vpn-vip-nodes-v31"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# 1. Argon2id Password Hashing (Backend & Admin Users)
# ---------------------------------------------------------------------------

def hash_password_argon2id(password: str) -> str:
    if not password or len(password) < 6:
        raise ValueError("Password must be at least 6 characters")
    salt = os.urandom(16)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_KIB,
    )
    digest = kdf.derive(password.encode("utf-8"))
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    dig_b64 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"argon2id$m={ARGON2_MEMORY_KIB},t={ARGON2_TIME_COST},p={ARGON2_LANES}${salt_b64}${dig_b64}"


def _b64u_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def verify_password_argon2id(password: str, encoded_hash: str) -> bool:
    if not password or not encoded_hash:
        return False
    try:
        scheme, params, salt_b64, dig_b64 = encoded_hash.split("$", 3)
        if scheme != "argon2id":
            return False
        kv = dict(item.split("=", 1) for item in params.split(","))
        salt = _b64u_decode(salt_b64)
        expected = _b64u_decode(dig_b64)
        kdf = Argon2id(
            salt=salt,
            length=len(expected),
            iterations=int(kv["t"]),
            lanes=int(kv["p"]),
            memory_cost=int(kv["m"]),
        )
        computed = kdf.derive(password.encode("utf-8"))
        return hmac.compare_digest(computed, expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 2. Cross-Platform Zero-Knowledge Envelope (PBKDF2-SHA256 + AES-256-GCM)
# ---------------------------------------------------------------------------

def compute_user_lookup_id(username: str) -> str:
    normalized = username.strip().lower().encode("utf-8")
    return hmac.new(USERNAME_LOOKUP_DOMAIN, normalized, hashlib.sha256).hexdigest()


def derive_pbkdf2_key(secret: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(secret.encode("utf-8"))


def encrypt_aes_gcm(key_32b: bytes, plaintext: bytes, aad: bytes = b"") -> str:
    """Returns base64(12B_nonce || ciphertext_with_16B_tag) — Android JCA & WebCrypto compatible."""
    nonce = os.urandom(12)
    ct = AESGCM(key_32b).encrypt(nonce, plaintext, aad or None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_aes_gcm(key_32b: bytes, token_b64: str, aad: bytes = b"") -> bytes:
    raw = base64.b64decode(token_b64)
    if len(raw) < 28:
        raise ValueError("Malformed AES-GCM payload")
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key_32b).decrypt(nonce, ct, aad or None)


def seal_user_license_envelope(
    username: str,
    password: str,
    salt_hex: str,
    license_payload: Dict[str, Any],
) -> str:
    salt = bytes.fromhex(salt_hex)
    norm_user = username.strip().lower()
    key = derive_pbkdf2_key(f"{norm_user}:{password}", salt)
    body = json.dumps(license_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return encrypt_aes_gcm(key, body, aad=norm_user.encode("utf-8"))


def open_user_license_envelope(
    username: str,
    password: str,
    salt_hex: str,
    envelope_b64: str,
) -> Dict[str, Any]:
    salt = bytes.fromhex(salt_hex)
    norm_user = username.strip().lower()
    key = derive_pbkdf2_key(f"{norm_user}:{password}", salt)
    plain = decrypt_aes_gcm(key, envelope_b64, aad=norm_user.encode("utf-8"))
    return json.loads(plain.decode("utf-8"))


def encrypt_vip_nodes_payload(vip_key_hex: str, nodes: list[Dict[str, Any]]) -> str:
    """Encrypts VIP Private Nodes with 256-bit AES-GCM so URIs never appear in plaintext in bundle.json."""
    if not nodes:
        return ""
    key = bytes.fromhex(vip_key_hex.strip())
    if len(key) != 32:
        raise ValueError("VIP content key must be 32 bytes (64 hex chars)")
    body = json.dumps(nodes, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    return encrypt_aes_gcm(key, body, aad=VIP_NODES_AAD)


def decrypt_vip_nodes_payload(vip_key_hex: str, token_b64: str) -> list[Dict[str, Any]]:
    if not token_b64 or not vip_key_hex:
        return []
    key = bytes.fromhex(vip_key_hex.strip())
    if len(key) != 32:
        raise ValueError("VIP content key must be 32 bytes (64 hex chars)")
    plain = decrypt_aes_gcm(key, token_b64, aad=VIP_NODES_AAD)
    parsed = json.loads(plain.decode("utf-8"))
    return parsed if isinstance(parsed, list) else []


# ---------------------------------------------------------------------------
# 3. ECDSA P-256 Signing & Verification (DER <-> P1363 interoperable)
# ---------------------------------------------------------------------------

def generate_ecdsa_p256_keypair() -> Tuple[str, str]:
    """Returns (private_pkcs8_b64, public_spki_b64)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_der = priv.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_der = priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(priv_der).decode("ascii"), base64.b64encode(pub_der).decode("ascii")


def canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")


def sign_ecdsa_der_b64(private_pkcs8_b64: str, data: bytes) -> str:
    priv = serialization.load_der_private_key(base64.b64decode(private_pkcs8_b64), password=None)
    assert isinstance(priv, ec.EllipticCurvePrivateKey)
    sig_der = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig_der).decode("ascii")


def p1363_to_der_signature(sig_64b: bytes) -> bytes:
    if len(sig_64b) != 64:
        raise ValueError("Expected 64-byte P1363 ECDSA signature")
    r = int.from_bytes(sig_64b[:32], "big")
    s = int.from_bytes(sig_64b[32:], "big")
    return encode_dss_signature(r, s)


def der_to_p1363_signature(sig_der: bytes) -> bytes:
    r, s = decode_dss_signature(sig_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_ecdsa_b64(public_spki_b64: str, data: bytes, signature_b64: str) -> bool:
    try:
        pub = serialization.load_der_public_key(base64.b64decode(public_spki_b64))
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        raw_sig = base64.b64decode(signature_b64)
        if len(raw_sig) == 64:
            raw_sig = p1363_to_der_signature(raw_sig)
        pub.verify(raw_sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 4. RFC 6238 TOTP (Admin Two-Factor Authentication)
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def compute_totp_code(secret_b32: str, unix_time: int | None = None, step_sec: int = 30) -> str:
    ts = int(time.time()) if unix_time is None else int(unix_time)
    clean = secret_b32.strip().upper().replace(" ", "")
    pad = "=" * ((8 - len(clean) % 8) % 8)
    key = base64.b32decode(clean + pad)
    counter = struct.pack(">Q", ts // step_sec)
    mac = hmac.new(key, counter, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"


def verify_totp_code(secret_b32: str, code: str, unix_time: int | None = None, window: int = 1) -> bool:
    clean_code = (code or "").strip()
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False
    ts = int(time.time()) if unix_time is None else int(unix_time)
    for delta in range(-window, window + 1):
        if hmac.compare_digest(compute_totp_code(secret_b32, ts + delta * 30), clean_code):
            return True
    return False


# ---------------------------------------------------------------------------
# 5. Encrypted SQLite Vault & Scheduled Encrypted Backups + Recovery
# ---------------------------------------------------------------------------

def encrypt_file_with_passphrase(src_path: Path, dst_path: Path, passphrase: str) -> Dict[str, Any]:
    raw_bytes = src_path.read_bytes()
    compressed = gzip.compress(raw_bytes, compresslevel=6)
    salt = os.urandom(16)
    key = derive_pbkdf2_key(passphrase, salt, iterations=PBKDF2_ITERATIONS)
    sha256_plain = hashlib.sha256(raw_bytes).hexdigest()
    meta = {
        "v": 1,
        "alg": "PBKDF2-SHA256+AES-256-GCM+GZIP",
        "iter": PBKDF2_ITERATIONS,
        "salt_hex": salt.hex(),
        "plain_sha256": sha256_plain,
        "plain_bytes": len(raw_bytes),
        "created_at": utc_now_iso(),
    }
    aad = canonical_json_bytes(meta)
    ciphertext_b64 = encrypt_aes_gcm(key, compressed, aad=aad)
    envelope = {"meta": meta, "ciphertext_b64": ciphertext_b64}
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst_path.with_suffix(dst_path.suffix + ".tmp")
    tmp.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    tmp.replace(dst_path)
    return meta


def decrypt_file_with_passphrase(enc_path: Path, dst_path: Path, passphrase: str) -> Dict[str, Any]:
    envelope = json.loads(enc_path.read_text(encoding="utf-8"))
    meta = envelope["meta"]
    salt = bytes.fromhex(meta["salt_hex"])
    key = derive_pbkdf2_key(passphrase, salt, iterations=int(meta["iter"]))
    aad = canonical_json_bytes(meta)
    compressed = decrypt_aes_gcm(key, envelope["ciphertext_b64"], aad=aad)
    raw_bytes = gzip.decompress(compressed)
    if hashlib.sha256(raw_bytes).hexdigest() != meta["plain_sha256"]:
        raise ValueError("Backup integrity SHA-256 mismatch!")
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst_path.with_suffix(dst_path.suffix + ".tmp")
    tmp.write_bytes(raw_bytes)
    tmp.replace(dst_path)
    return meta


def create_encrypted_sqlite_backup(
    db_path: Path,
    backup_dir: Path,
    passphrase: str,
    retain_count: int = 14,
) -> Path:
    """Uses SQLite online backup API for transactional consistency, then encrypts with AES-256-GCM."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snap_tmp = backup_dir / f".snap_{stamp}.sqlite"
    try:
        src_conn = sqlite3.connect(str(db_path))
        dst_conn = sqlite3.connect(str(snap_tmp))
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
            src_conn.close()
        out_enc = backup_dir / f"backup_{stamp}.sqlite.enc.json"
        encrypt_file_with_passphrase(snap_tmp, out_enc, passphrase)
    finally:
        if snap_tmp.exists():
            snap_tmp.unlink()

    backups = sorted(backup_dir.glob("backup_*.sqlite.enc.json"))
    if retain_count > 0 and len(backups) > retain_count:
        for stale in backups[:-retain_count]:
            stale.unlink(missing_ok=True)
    return out_enc


def restore_encrypted_sqlite_backup(enc_backup_path: Path, target_db_path: Path, passphrase: str) -> Dict[str, Any]:
    restored_tmp = target_db_path.with_suffix(".restoring.sqlite")
    meta = decrypt_file_with_passphrase(enc_backup_path, restored_tmp, passphrase)
    # Verify SQLite PRAGMA integrity_check before swapping live DB
    conn = sqlite3.connect(str(restored_tmp))
    try:
        chk = conn.execute("PRAGMA integrity_check;").fetchone()
        if not chk or chk[0] != "ok":
            raise ValueError(f"Restored SQLite failed integrity_check: {chk}")
    finally:
        conn.close()
    shutil.move(str(restored_tmp), str(target_db_path))
    return meta
