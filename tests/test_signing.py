"""서명(RSA/ECDSA) 라운드트립 테스트."""

from __future__ import annotations

import pytest
from unittest.mock import patch

from ciphers import keystore
import signing


@pytest.fixture(params=["rsa", "ecdsa"])
def algo(request):
    return request.param


@pytest.fixture()
def sign_keys(tmp_path, algo):
    bits = 1024 if algo == "rsa" else 2048
    with patch.object(keystore, "KEYS_DIR", str(tmp_path)):
        keystore.generate_sign_keys(algo, bits)
        yield tmp_path


def test_sign_verify_valid(tmp_path, sign_keys, algo):
    msg = b"test message"
    with patch.object(keystore, "KEYS_DIR", str(sign_keys)):
        sig = signing.sign(algo, msg)
        assert signing.verify(algo, msg, sig) is True


def test_verify_tampered_message(tmp_path, sign_keys, algo):
    msg = b"original"
    with patch.object(keystore, "KEYS_DIR", str(sign_keys)):
        sig = signing.sign(algo, msg)
        assert signing.verify(algo, b"tampered", sig) is False


def test_verify_tampered_signature(tmp_path, sign_keys, algo):
    msg = b"hello"
    with patch.object(keystore, "KEYS_DIR", str(sign_keys)):
        sig = signing.sign(algo, msg)
        bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        assert signing.verify(algo, msg, bad_sig) is False


def test_no_keys_raises(tmp_path, algo):
    with patch.object(keystore, "KEYS_DIR", str(tmp_path)):
        with pytest.raises(ValueError, match="키 파일"):
            signing.sign(algo, b"msg")
