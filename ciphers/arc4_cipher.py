"""ARC4(RC4) 스트림 암호 — 메시지 + 파일 모드.

원본: Code_2-3-arc4.py (메시지 전용). 파일 모드는 새로 추가했다.
- 키 = keytext.encode() 를 그대로(raw) 사용 (SHA256 해시 없음, IV 없음, 패딩 없음).
- 스트림 암호라 enc/dec 연산이 대칭이다. 블록/헤더/filler 개념이 없어
  블록 암호 파일 모드의 청크 버그가 애초에 존재하지 않는다.
- 인터페이스 통일을 위해 ivtext 인자를 받지만 무시한다.
"""

from __future__ import annotations

from Crypto.Cipher import ARC4

KSIZE = 1024


class Arc4Cipher:
    block_size = 1  # 스트림: 어떤 길이의 암호문도 유효

    def __init__(self, keytext: str, ivtext: str | None = None) -> None:
        # ivtext는 인터페이스 통일용으로만 받고 사용하지 않는다.
        self.key = keytext.encode("utf-8")

    def _new_cipher(self):
        return ARC4.new(self.key)

    # ----- 메시지 모드 -----
    def encrypt(self, plaintext: str) -> bytes:
        return self._new_cipher().encrypt(plaintext.encode("utf-8"))

    def decrypt(self, ciphertext: bytes) -> str:
        return self._new_cipher().decrypt(ciphertext).decode("utf-8")

    # ----- 파일 모드 (스트림: enc == dec, 청크를 순서대로 흘려보냄) -----
    def _process_file(self, in_path: str, out_path: str) -> None:
        cipher = self._new_cipher()  # 파일 전체에 대해 단일 keystream
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            while True:
                chunk = fin.read(KSIZE)
                if not chunk:
                    break
                fout.write(cipher.encrypt(chunk))

    def encrypt_file(self, in_path: str, out_path: str) -> None:
        self._process_file(in_path, out_path)

    def decrypt_file(self, in_path: str, out_path: str) -> None:
        self._process_file(in_path, out_path)
