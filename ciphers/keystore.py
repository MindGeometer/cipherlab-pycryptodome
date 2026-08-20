"""키 파일 관리 — RSA 암호용 및 전자서명용 PEM 키쌍을 keys/에 저장·관리한다."""

from __future__ import annotations

import os

from Crypto.PublicKey import ECC, RSA

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS_DIR = os.path.join(BASE_DIR, "keys")
os.makedirs(KEYS_DIR, exist_ok=True)


def _path(name: str) -> str:
    return os.path.join(KEYS_DIR, name)


# ---------- RSA 암호용 ----------

def generate_rsa_enc(bits: int = 2048) -> None:
    key = RSA.generate(bits)
    with open(_path("enc_rsa_private.pem"), "wb") as f:
        f.write(key.export_key("PEM"))
    with open(_path("enc_rsa_public.pem"), "wb") as f:
        f.write(key.publickey().export_key("PEM"))


def enc_keys_exist() -> bool:
    return os.path.exists(_path("enc_rsa_private.pem")) and os.path.exists(
        _path("enc_rsa_public.pem")
    )


def enc_key_bits() -> int | None:
    p = _path("enc_rsa_public.pem")
    if not os.path.exists(p):
        return None
    with open(p, "rb") as f:
        return RSA.import_key(f.read()).size_in_bits()


# ---------- 전자서명용 ----------

def generate_sign_keys(algo: str, bits: int = 2048) -> None:
    if algo == "rsa":
        key = RSA.generate(bits)
        with open(_path("sign_rsa_private.pem"), "wb") as f:
            f.write(key.export_key("PEM"))
        with open(_path("sign_rsa_public.pem"), "wb") as f:
            f.write(key.publickey().export_key("PEM"))
    elif algo == "ecdsa":
        key = ECC.generate(curve="P-256")
        with open(_path("sign_ecdsa_private.pem"), "w") as f:
            f.write(key.export_key(format="PEM"))
        with open(_path("sign_ecdsa_public.pem"), "w") as f:
            f.write(key.public_key().export_key(format="PEM"))
    else:
        raise ValueError(f"알 수 없는 알고리즘: {algo}")


def sign_rsa_key_bits() -> int | None:
    p = _path("sign_rsa_public.pem")
    if not os.path.exists(p):
        return None
    with open(p, "rb") as f:
        return RSA.import_key(f.read()).size_in_bits()


def sign_keys_exist(algo: str) -> bool:
    if algo == "rsa":
        return os.path.exists(_path("sign_rsa_private.pem")) and os.path.exists(
            _path("sign_rsa_public.pem")
        )
    if algo == "ecdsa":
        return os.path.exists(_path("sign_ecdsa_private.pem")) and os.path.exists(
            _path("sign_ecdsa_public.pem")
        )
    return False
