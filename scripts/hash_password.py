#!/usr/bin/env python3
"""One-shot password hasher matching hashPassword() in source/ircfiber/auth.d.

Outputs the Base64(salt || sha256_pbkdf2(password)) hash so the live
Mongo users collection can be reset via mongosh.

Usage:
  ./hash_password.py "new-password"   # → prints just the hash
  ./hash_password.py                  # defaults to 'REDACTED'
"""
import sys, os, hashlib, base64

SALT_LEN = 16
HASH_LEN = 32
ITERATIONS = 10_000

def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(SALT_LEN)
    h = hashlib.sha256(password.encode("utf-8") + salt).digest()
    for _ in range(ITERATIONS):
        h = hashlib.sha256(h + salt + password.encode("utf-8")).digest()
    return base64.b64encode(salt + h).decode("ascii")

if __name__ == "__main__":
    pw = sys.argv[1] if len(sys.argv) > 1 else "REDACTED"
    print(hash_password(pw))
