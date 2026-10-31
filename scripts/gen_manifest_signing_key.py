#!/usr/bin/env python3
"""Generate the ECDSA P-256 key pair used to sign top500.manifest.json.

Run locally (never in CI):  python scripts/gen_manifest_signing_key.py
  • PRIVATE value -> add as repository secret TOP500_SIGNING_KEY_B64 (never commit it)
  • PUBLIC value  -> put in android/gradle.properties as top500PublicKeyB64=...
"""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1())
priv = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
print("TOP500_SIGNING_KEY_B64 (secret, keep private):")
print(base64.b64encode(priv).decode())
print()
print("top500PublicKeyB64 (public, commit to android/gradle.properties):")
print(base64.b64encode(pub).decode())
