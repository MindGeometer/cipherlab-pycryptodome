"""3DES(Triple DES) CBC 암호 — 메시지 + 파일 모드.

원본: Code_2-1-3desformsg.py (메시지), Code_2-4-3desforfile.py (파일).
- key = SHA256(keytext)[:24] (3-key 3DES), iv = SHA256(keytext+ivtext)[:8], block 8.
- 원본 메시지 코드는 패딩이 없어 8배수 아닌 입력에서 crash했으나,
  여기서는 AES 메시지와 동일한 header+filler(block 8)를 적용해 임의 입력을 지원한다.
"""

from __future__ import annotations

from Crypto.Cipher import DES3

from .base import CbcBlockCipher


class Des3Cipher(CbcBlockCipher):
    block_size = 8
    key_len = 24

    def _new_cipher(self):
        return DES3.new(self.key, DES3.MODE_CBC, self.iv)
