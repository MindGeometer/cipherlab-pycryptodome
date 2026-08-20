"""RsaCipher 라운드트립 테스트."""

from __future__ import annotations

import os
import pytest
from unittest.mock import patch

from ciphers import keystore
from ciphers.rsa_cipher import RsaCipher


@pytest.fixture()
def rsa_keys(tmp_path):
    """임시 keys/ 디렉터리에 RSA 키쌍을 생성하고 KEYS_DIR를 패치한다."""
    with patch.object(keystore, "KEYS_DIR", str(tmp_path)):
        keystore.generate_rsa_enc(bits=1024)
        yield tmp_path


@pytest.fixture()
def cipher(rsa_keys):
    with patch.object(keystore, "KEYS_DIR", str(rsa_keys)):
        yield RsaCipher()


# ---------- 메시지 모드 ----------

def test_message_roundtrip(cipher):
    msg = "hello RSA"
    assert cipher.decrypt(cipher.encrypt(msg)) == msg


def test_message_utf8(cipher):
    msg = "안녕하세요 RSA"
    assert cipher.decrypt(cipher.encrypt(msg)) == msg


def test_message_too_long(cipher):
    # 1024비트 OAEP-SHA256 한계 = 62바이트
    long_msg = "x" * 63
    with pytest.raises(ValueError, match="RSA-OAEP"):
        cipher.encrypt(long_msg)


# ---------- 파일 모드 ----------

@pytest.mark.parametrize("size", [0, 1, 62, 63, 100, 1024, 2048])
def test_file_roundtrip(tmp_path, cipher, size):
    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    in_file = tmp_path / "plain.bin"
    enc_file = tmp_path / "plain.enc"
    dec_file = tmp_path / "plain.dec"
    in_file.write_bytes(data)
    cipher.encrypt_file(str(in_file), str(enc_file))
    cipher.decrypt_file(str(enc_file), str(dec_file))
    assert dec_file.read_bytes() == data


def test_no_keys_raises(tmp_path):
    with patch.object(keystore, "KEYS_DIR", str(tmp_path)):
        with pytest.raises(ValueError, match="키쌍"):
            RsaCipher()
