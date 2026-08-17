"""AES CBC 암호 — 메시지 + 파일 모드.

원본: Code_2-2-aesformsg.py (메시지), Code_2-5-aesforfile.py (파일).
- key = SHA256(keytext)[:16] (AES-128), iv = SHA256(keytext+ivtext)[:16], block 16.
- header+filler 패딩은 원본과 동일하며, 파일 모드의 청크 버그만 수정했다(base.py 참고).
"""

from __future__ import annotations

from Crypto.Cipher import AES

from .base import CbcBlockCipher


class AesCipher(CbcBlockCipher):
    block_size = 16
    key_len = 16

    def _new_cipher(self):
        return AES.new(self.key, AES.MODE_CBC, self.iv)
