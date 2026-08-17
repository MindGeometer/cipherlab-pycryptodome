"""3DES/AES/ARC4 메시지·파일 라운드트립 테스트.

파일 모드에서 원본 책 코드의 두 버그를 유발하는 엣지 크기를 포함한다:
  - BUG 1: 단일 read + header+filesize >= KSIZE(1024) → 암호화 시 padding 오류
  - BUG 2: 암호문 본문이 KSIZE 배수 → 복호화 시 filler 미제거
"""

import os

import pytest

from ciphers import get_file_cipher, get_message_cipher

KEY, IV = "samsjang", "1234"
CIPHERS = ["des3", "aes", "arc4"]
BLOCK = {"des3": 8, "aes": 16, "arc4": 1}

MESSAGES = [
    "",
    "python3x",       # 8배수 정렬
    "python35ab",     # 비정렬 (원본 3DES 메시지가 crash하던 케이스)
    "x" * 40,
    "한글 테스트 メッセージ 🔐",  # 멀티바이트 UTF-8
]

# BUG1(3DES 1017~1023, AES 1009~1023), BUG2(본문 1024/2048 배수) 포함
FILE_SIZES = [
    0, 1, 5, 7, 8, 9, 15, 16, 17,
    1009, 1015, 1016, 1017, 1018, 1020, 1023, 1024, 1025,
    2040, 2044, 2047, 2048, 2049, 5000, 8192,
]


@pytest.mark.parametrize("name", CIPHERS)
@pytest.mark.parametrize("msg", MESSAGES)
def test_message_roundtrip(name, msg):
    ct = get_message_cipher(name, KEY, IV).encrypt(msg)
    pt = get_message_cipher(name, KEY, IV).decrypt(ct)
    assert pt == msg


def test_arc4_ignores_iv():
    """ARC4는 IV를 무시해야 한다 (iv를 바꿔도 결과 동일)."""
    a = get_message_cipher("arc4", KEY, "aaaa").encrypt("hello world")
    b = get_message_cipher("arc4", KEY, "zzzz").encrypt("hello world")
    assert a == b


@pytest.mark.parametrize("name", CIPHERS)
@pytest.mark.parametrize("size", FILE_SIZES)
def test_file_roundtrip(name, size, tmp_path):
    data = os.urandom(size)
    p_in = tmp_path / "in.bin"
    p_enc = tmp_path / "in.bin.enc"
    p_dec = tmp_path / "in.bin.dec"
    p_in.write_bytes(data)

    get_file_cipher(name, KEY, IV).encrypt_file(str(p_in), str(p_enc))
    get_file_cipher(name, KEY, IV).decrypt_file(str(p_enc), str(p_dec))

    out = p_dec.read_bytes()
    assert out == data, f"{name} size={size}: 복호 길이 {len(out)} != {size}"

    # 암호문 크기 검증
    encsize = p_enc.stat().st_size
    if name == "arc4":
        assert encsize == size  # 스트림: 길이 보존
    else:
        block = BLOCK[name]
        filler = (block - size % block) % block
        assert encsize == block + size + filler
