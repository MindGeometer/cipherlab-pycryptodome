"""전자서명 — RSA(PKCS#1 v1.5)와 ECDSA(P-256)를 지원한다.

원본: Code_3-4-rsa_sign.py, Code_3-6-ecdsa_sign.py (WhiteHatPython 3장).
"""

from __future__ import annotations

import os

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15

from ciphers import keystore

ALGOS: dict[str, str] = {
    "rsa": "RSA (PKCS#1 v1.5 + SHA-256)",
    "ecdsa": "ECDSA (P-256 + SHA-256)",
}


def _load(name: str, binary: bool = True):
    p = os.path.join(keystore.KEYS_DIR, name)
    if not os.path.exists(p):
        raise ValueError(f"키 파일이 없습니다: {name}. 먼저 키를 생성하세요.")
    mode = "rb" if binary else "r"
    with open(p, mode) as f:
        return f.read()


def sign(algo: str, message: bytes) -> bytes:
    h = SHA256.new(message)
    if algo == "rsa":
        key = RSA.import_key(_load("sign_rsa_private.pem"))
        return pkcs1_15.new(key).sign(h)
    if algo == "ecdsa":
        key = ECC.import_key(_load("sign_ecdsa_private.pem", binary=False))
        return DSS.new(key, "fips-186-3").sign(h)
    raise ValueError(f"알 수 없는 알고리즘: {algo}")


def verify(algo: str, message: bytes, signature: bytes) -> bool:
    h = SHA256.new(message)
    try:
        if algo == "rsa":
            key = RSA.import_key(_load("sign_rsa_public.pem"))
            pkcs1_15.new(key).verify(h, signature)
        elif algo == "ecdsa":
            key = ECC.import_key(_load("sign_ecdsa_public.pem", binary=False))
            DSS.new(key, "fips-186-3").verify(h, signature)
        else:
            raise ValueError(f"알 수 없는 알고리즘: {algo}")
        return True
    except (ValueError, TypeError):
        return False
