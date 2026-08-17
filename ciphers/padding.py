"""공용 header + filler 패딩 헬퍼 (3DES/AES 공용, block_size 파라미터화).

WhiteHatPython 책의 방식을 그대로 유지한다:
  - 평문 뒤에 '0' 문자를 filler로 붙여 block_size의 배수로 맞춘다.
  - 몇 개를 붙였는지(fillersize)를 block_size 바이트짜리 header에 기록한다.
    header = str(fillersize) + '#' * (block_size - len(str(fillersize)))
    예) 3DES(block 8)에서 filler 3개  -> "3#######"
        AES(block 16)에서 filler 0개 -> "0###############"

fillersize의 최댓값은 block_size-1 (7 또는 15)이므로 str(fillersize)는 최대 2자리,
block_size(8/16) 바이트 header 안에 항상 들어간다.
"""


def make_header_and_filler(data_len: int, block_size: int) -> tuple[str, str]:
    """data_len 바이트 데이터를 block_size 배수로 맞추기 위한 (header, filler)를 만든다."""
    fillersize = (block_size - data_len % block_size) % block_size
    header = str(fillersize)
    header += "#" * (block_size - len(header))
    filler = "0" * fillersize
    return header, filler


def apply_message_padding(plaintext: str, block_size: int) -> bytes:
    """평문 문자열에 header+filler를 적용해 CBC 암호화용 바이트로 만든다.

    반환 레이아웃: header(block_size) + plaintext + filler,
    전체 길이는 항상 block_size의 배수.

    filler 개수는 '문자 수'가 아니라 UTF-8 '바이트 수' 기준으로 계산한다.
    (원본 책 코드는 문자 수로 계산해 한글 등 멀티바이트 입력에서 정렬이 깨졌다.)
    """
    pt_bytes = plaintext.encode("utf-8")
    header, filler = make_header_and_filler(len(pt_bytes), block_size)
    return header.encode("utf-8") + pt_bytes + filler.encode("utf-8")


def strip_message_padding(decrypted: bytes, block_size: int) -> bytes:
    """apply_message_padding으로 만든 복호 결과에서 header/filler를 제거해 원본 바이트를 돌려준다."""
    header = decrypted[:block_size].decode("utf-8")
    fillersize = int(header.split("#")[0])
    body = decrypted[block_size:]
    if fillersize:
        body = body[:-fillersize]
    return body
