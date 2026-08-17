"""암호 레지스트리 — 이름으로 암호 인스턴스를 생성하고 UI 메타데이터를 제공한다.

지원 암호: des3, aes, arc4. 모두 메시지 + 파일 모드를 지원한다.
"""

from __future__ import annotations

from .aes_cipher import AesCipher
from .arc4_cipher import Arc4Cipher
from .des3_cipher import Des3Cipher

# UI/라우팅에서 참조하는 암호 메타데이터.
#   uses_iv: IV(ivtext) 입력을 노출할지 여부 (ARC4는 IV 없음)
CIPHERS: dict[str, dict] = {
    "des3": {
        "cls": Des3Cipher,
        "name": "3DES",
        "full_name": "Triple DES (CBC)",
        "uses_iv": True,
        "tagline": "64비트 블록 · 168비트 키 · SHA256 파생 키/IV",
        "description": "DES를 세 번 겹친 블록 암호입니다. 키 24바이트, 블록 8바이트(64비트), CBC 운용 모드를 사용하며, 키·IV는 패스프레이즈의 SHA256 해시에서 유도합니다.",
    },
    "aes": {
        "cls": AesCipher,
        "name": "AES",
        "full_name": "AES-128 (CBC)",
        "uses_iv": True,
        "tagline": "128비트 블록 · 128비트 키 · SHA256 파생 키/IV",
        "description": "현대 표준 블록 암호입니다. 키 16바이트(AES-128), 블록 16바이트(128비트), CBC 운용 모드를 사용하며, 키·IV는 패스프레이즈의 SHA256 해시에서 유도합니다.",
    },
    "arc4": {
        "cls": Arc4Cipher,
        "name": "ARC4",
        "full_name": "ARC4 / RC4 (stream)",
        "uses_iv": False,
        "tagline": "스트림 암호 · raw 키 · IV/패딩 없음",
        "description": "패스프레이즈 바이트를 그대로 키로 쓰는 스트림 암호입니다. 키 길이는 1~256바이트로 가변이며, 블록·운용 모드·IV·패딩이 없습니다.",
    },
}


def is_valid(name: str) -> bool:
    return name in CIPHERS


def get_meta(name: str) -> dict:
    return CIPHERS[name]


def _make(name: str, keytext: str, ivtext: str = ""):
    if name not in CIPHERS:
        raise KeyError(f"알 수 없는 암호: {name}")
    cls = CIPHERS[name]["cls"]
    if CIPHERS[name]["uses_iv"]:
        return cls(keytext, ivtext)
    return cls(keytext)


def get_message_cipher(name: str, keytext: str, ivtext: str = ""):
    """메시지 모드 암호 인스턴스를 생성한다."""
    return _make(name, keytext, ivtext)


def get_file_cipher(name: str, keytext: str, ivtext: str = ""):
    """파일 모드 암호 인스턴스를 생성한다. (3종 모두 파일 모드 지원)"""
    return _make(name, keytext, ivtext)
