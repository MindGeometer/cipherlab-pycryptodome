"""RSA-OAEP 암호 — 메시지 + 파일 모드.

원본: Code_3-3-rsa.py (WhiteHatPython 3장).
- 공개키/개인키는 keys/ 디렉터리의 PEM 파일에서 로드한다.
- 메시지 모드: 단일 블록 OAEP 암호화 (키 크기 - 66바이트 한계).
- 파일 모드: max_chunk 단위로 분할 → 블록마다 OAEP 암호화 → key_bytes 블록 연결.
"""

from __future__ import annotations

import os

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from . import keystore

_HASH_LEN = 32  # SHA-256 출력 길이


class RsaCipher:
    def __init__(self, keytext: str = "", ivtext: str = "") -> None:
        if not keystore.enc_keys_exist():
            raise ValueError("먼저 'RSA 키 생성'으로 키쌍을 만드세요.")
        with open(os.path.join(keystore.KEYS_DIR, "enc_rsa_public.pem"), "rb") as f:
            self._pub = RSA.import_key(f.read())
        with open(os.path.join(keystore.KEYS_DIR, "enc_rsa_private.pem"), "rb") as f:
            self._priv = RSA.import_key(f.read())
        self._key_bytes: int = self._pub.size_in_bytes()
        # OAEP-SHA256: max plaintext = key_bytes - 2*hash_len - 2
        self._max_chunk: int = self._key_bytes - 2 * _HASH_LEN - 2

    def _enc(self) -> PKCS1_OAEP.PKCS1OAEP_Cipher:
        return PKCS1_OAEP.new(self._pub, hashAlgo=SHA256)

    def _dec(self) -> PKCS1_OAEP.PKCS1OAEP_Cipher:
        return PKCS1_OAEP.new(self._priv, hashAlgo=SHA256)

    # ----- 메시지 모드 -----

    def encrypt(self, plaintext: str) -> bytes:
        data = plaintext.encode("utf-8")
        if len(data) > self._max_chunk:
            raise ValueError(
                f"RSA-OAEP는 {self._key_bytes * 8}비트 키 기준 "
                f"최대 {self._max_chunk}바이트 평문만 암호화할 수 있습니다 "
                f"(입력: {len(data)}바이트). RSA는 짧은 데이터용 암호입니다."
            )
        return self._enc().encrypt(data)

    def decrypt(self, ciphertext: bytes) -> str:
        return self._dec().decrypt(ciphertext).decode("utf-8")

    # ----- 파일 모드 -----

    def encrypt_file(self, in_path: str, out_path: str) -> None:
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            while True:
                chunk = fin.read(self._max_chunk)
                if not chunk:
                    break
                fout.write(self._enc().encrypt(chunk))

    def decrypt_file(self, in_path: str, out_path: str) -> None:
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            while True:
                block = fin.read(self._key_bytes)
                if not block:
                    break
                fout.write(self._dec().decrypt(block))
