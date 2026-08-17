"""3DES/AES가 공유하는 CBC 블록 암호 베이스.

WhiteHatPython 책의 인터페이스(passphrase -> SHA256 -> key/iv, header+filler 패딩)를
그대로 유지하되, 파일 모드의 두 버그를 수정한 버전이다.

수정한 버그 (원인: "마지막 청크"를 len(chunk) < KSIZE 로 판별한 것):
  BUG 1 (암호화 실패): 단일 read에 다 들어가고 header+filesize >= KSIZE 인 파일
     (예: 3DES 1017~1023B)은 filler가 안 붙어 encrypt()가 padding 오류를 냈다.
     -> filler를 read 루프 이후에 filesize 기반으로 무조건 붙인다.
  BUG 2 (복호화 오작동): 암호문 본문(헤더 제외)이 정확히 KSIZE 배수면 마지막 read가
     딱 KSIZE라 filler 제거가 실행되지 않아 '0' filler가 잔존했다.
     -> 전체 크기로 remaining을 계산해 remaining == 0 으로 마지막 청크를 판별한다.
"""

from __future__ import annotations

from Crypto.Hash import SHA256

from . import padding

KSIZE = 1024  # 파일 입출력 청크 크기 (8, 16 모두의 배수)


class CbcBlockCipher:
    """CBC 모드 블록 암호 베이스. 서브클래스가 block_size/key_len/_new_cipher를 정의한다."""

    block_size: int
    key_len: int

    def __init__(self, keytext: str, ivtext: str) -> None:
        # 책 원본과 동일하게 '같은 hash 객체'에 누적 update 한다.
        # -> key = SHA256(keytext)[:key_len], iv = SHA256(keytext+ivtext)[:block_size]
        h = SHA256.new()
        h.update(keytext.encode("utf-8"))
        self.key = h.digest()[: self.key_len]
        h.update(ivtext.encode("utf-8"))
        self.iv = h.digest()[: self.block_size]

    def _new_cipher(self):  # pragma: no cover - 서브클래스에서 구현
        raise NotImplementedError

    # ----- 메시지 모드 -----
    def encrypt(self, plaintext: str) -> bytes:
        data = padding.apply_message_padding(plaintext, self.block_size)
        return self._new_cipher().encrypt(data)

    def decrypt(self, ciphertext: bytes) -> str:
        if len(ciphertext) % self.block_size != 0:
            raise ValueError(
                f"암호문 길이가 블록 크기({self.block_size})의 배수가 아닙니다."
            )
        decrypted = self._new_cipher().decrypt(ciphertext)
        return padding.strip_message_padding(decrypted, self.block_size).decode("utf-8")

    # ----- 파일 모드 -----
    def encrypt_file(self, in_path: str, out_path: str) -> None:
        import os

        block = self.block_size
        filesize = os.path.getsize(in_path)
        fillersize = (block - filesize % block) % block
        header, filler = padding.make_header_and_filler(filesize, block)

        cipher = self._new_cipher()
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            buffer = header.encode("utf-8")  # block 크기의 헤더
            while True:
                chunk = fin.read(KSIZE)
                if not chunk:
                    break
                buffer += chunk
                # KSIZE(=block 정렬) 단위로 가능한 만큼 flush
                while len(buffer) >= KSIZE:
                    fout.write(cipher.encrypt(buffer[:KSIZE]))
                    buffer = buffer[KSIZE:]
            # 루프 종료 후 filler를 '무조건' 붙인다 (BUG 1 fix).
            buffer += filler.encode("utf-8")
            # 이 시점 buffer 길이는 block 배수 보장 (header + filesize + fillersize).
            if buffer:
                fout.write(cipher.encrypt(buffer))

    def decrypt_file(self, in_path: str, out_path: str) -> None:
        import os

        block = self.block_size
        encsize = os.path.getsize(in_path)
        cipher = self._new_cipher()
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            header = cipher.decrypt(fin.read(block))
            fillersize = int(header.split(b"#")[0])
            remaining = encsize - block  # 아직 읽어야 할 암호문 본문 바이트 수
            while remaining > 0:
                n = min(KSIZE, remaining)
                dec = cipher.decrypt(fin.read(n))
                remaining -= n
                if remaining == 0 and fillersize:  # 크기 기반 마지막 청크 판별 (BUG 2 fix)
                    dec = dec[:-fillersize]
                fout.write(dec)
