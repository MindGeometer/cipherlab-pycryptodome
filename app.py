"""ToolApp — 3DES/AES/ARC4/RSA 암호화·복호화 + RSA/ECDSA 전자서명 웹 앱 (Flask).

WhiteHatPython 책의 Code_2-*/3-* 예제(pycryptodome 기반)를 웹으로 옮긴 것.
- 암호별 페이지: /des3, /aes, /arc4, /rsa
- 메시지 모드 API: /api/<cipher>/message/(encrypt|decrypt)  (base64/hex 토글)
- 파일 모드 API:  /api/<cipher>/file/(encrypt|decrypt)       (업로드 -> .enc/.dec 다운로드)
- RSA 키 관리:   /api/rsa/keygen, /api/rsa/keys
- 전자서명 페이지: /sign
- 서명 API:      /api/sign/(keygen|keys|sign|verify)
"""

from __future__ import annotations

import base64
import binascii
import os
import uuid

from flask import (
    Flask,
    abort,
    after_this_request,
    jsonify,
    render_template,
    request,
    send_file,
)
from werkzeug.utils import secure_filename

import signing
from ciphers import CIPHERS, get_file_cipher, get_message_cipher, is_valid
from ciphers import keystore

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("TOOLAPP_SECRET", "toolapp-dev-secret")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25MB


# ---------- 인코딩 헬퍼 (메시지 모드) ----------
def encode_bytes(data: bytes, encoding: str) -> str:
    if encoding == "hex":
        return data.hex()
    return base64.b64encode(data).decode("ascii")


def decode_text(text: str, encoding: str) -> bytes:
    text = text.strip()
    try:
        if encoding == "hex":
            return bytes.fromhex(text)
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"입력이 올바른 {encoding} 형식이 아닙니다.")


# ---------- 페이지 ----------
@app.route("/")
def index():
    return render_template("index.html", ciphers=CIPHERS)


@app.route("/<cipher>")
def cipher_page(cipher: str):
    if not is_valid(cipher):
        abort(404)
    meta = CIPHERS[cipher]
    tmpl = meta.get("template", "cipher.html")
    return render_template(tmpl, cipher=cipher, meta=meta, ciphers=CIPHERS)


@app.route("/sign")
def sign_page():
    return render_template("sign.html", ciphers=CIPHERS, algos=signing.ALGOS)


# ---------- 메시지 모드 API ----------
@app.route("/api/<cipher>/message/encrypt", methods=["POST"])
def api_message_encrypt(cipher: str):
    if not is_valid(cipher):
        abort(404)
    data = request.get_json(silent=True) or {}
    keytext = data.get("keytext", "")
    ivtext = data.get("ivtext", "")
    plaintext = data.get("plaintext", "")
    encoding = data.get("encoding", "base64")
    if CIPHERS[cipher].get("needs_passphrase", True) and not keytext:
        return jsonify(error="키(패스프레이즈)를 입력하세요."), 400
    try:
        c = get_message_cipher(cipher, keytext, ivtext)
        ct = c.encrypt(plaintext)
        return jsonify(ciphertext=encode_bytes(ct, encoding), encoding=encoding)
    except Exception as e:  # noqa: BLE001 - 사용자에게 읽기 쉬운 메시지로 변환
        return jsonify(error=str(e)), 400


@app.route("/api/<cipher>/message/decrypt", methods=["POST"])
def api_message_decrypt(cipher: str):
    if not is_valid(cipher):
        abort(404)
    data = request.get_json(silent=True) or {}
    keytext = data.get("keytext", "")
    ivtext = data.get("ivtext", "")
    ciphertext = data.get("ciphertext", "")
    encoding = data.get("encoding", "base64")
    if CIPHERS[cipher].get("needs_passphrase", True) and not keytext:
        return jsonify(error="키(패스프레이즈)를 입력하세요."), 400
    try:
        raw = decode_text(ciphertext, encoding)
        c = get_message_cipher(cipher, keytext, ivtext)
        pt = c.decrypt(raw)
        return jsonify(plaintext=pt)
    except UnicodeDecodeError:
        return jsonify(error="복호화 결과가 올바른 텍스트가 아닙니다. 키/IV/인코딩을 확인하세요."), 400
    except Exception as e:  # noqa: BLE001
        return jsonify(error=str(e)), 400


# ---------- 파일 모드 API ----------
def _save_upload() -> tuple[str, str]:
    """업로드 파일을 uploads/에 저장하고 (임시 입력경로, 원본 파일명)을 반환한다."""
    if "file" not in request.files or request.files["file"].filename == "":
        raise ValueError("파일을 선택하세요.")
    f = request.files["file"]
    original = secure_filename(f.filename) or "file"
    in_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}_{original}")
    f.save(in_path)
    return in_path, original


def _cleanup(*paths: str):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


@app.route("/api/<cipher>/file/encrypt", methods=["POST"])
def api_file_encrypt(cipher: str):
    if not is_valid(cipher):
        abort(404)
    keytext = request.form.get("keytext", "")
    ivtext = request.form.get("ivtext", "")
    if CIPHERS[cipher].get("needs_passphrase", True) and not keytext:
        return jsonify(error="키(패스프레이즈)를 입력하세요."), 400
    try:
        in_path, original = _save_upload()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    out_path = in_path + ".enc"
    download_name = original + ".enc"
    try:
        get_file_cipher(cipher, keytext, ivtext).encrypt_file(in_path, out_path)
    except Exception as e:  # noqa: BLE001
        _cleanup(in_path, out_path)
        return jsonify(error=str(e)), 400

    @after_this_request
    def _remove(response):
        _cleanup(in_path, out_path)
        return response

    return send_file(
        out_path, as_attachment=True, download_name=download_name,
        mimetype="application/octet-stream",
    )


@app.route("/api/<cipher>/file/decrypt", methods=["POST"])
def api_file_decrypt(cipher: str):
    if not is_valid(cipher):
        abort(404)
    keytext = request.form.get("keytext", "")
    ivtext = request.form.get("ivtext", "")
    if CIPHERS[cipher].get("needs_passphrase", True) and not keytext:
        return jsonify(error="키(패스프레이즈)를 입력하세요."), 400
    try:
        in_path, original = _save_upload()
    except ValueError as e:
        return jsonify(error=str(e)), 400
    out_path = in_path + ".dec"
    # 원본이 name.enc 이면 name 으로, 아니면 name.dec 으로 내려준다.
    download_name = original[:-4] if original.endswith(".enc") else original + ".dec"
    try:
        get_file_cipher(cipher, keytext, ivtext).decrypt_file(in_path, out_path)
    except Exception as e:  # noqa: BLE001
        _cleanup(in_path, out_path)
        return jsonify(error="복호화 실패: 키/IV 또는 파일 형식을 확인하세요."), 400

    @after_this_request
    def _remove(response):
        _cleanup(in_path, out_path)
        return response

    return send_file(
        out_path, as_attachment=True, download_name=download_name,
        mimetype="application/octet-stream",
    )


@app.errorhandler(413)
def too_large(e):
    return jsonify(error="파일이 너무 큽니다(최대 25MB)."), 413


# ---------- RSA 키 관리 API ----------

@app.route("/api/rsa/keygen", methods=["POST"])
def api_rsa_keygen():
    data = request.get_json(silent=True) or {}
    bits = data.get("bits", 2048)
    try:
        bits = int(bits)
    except (TypeError, ValueError):
        return jsonify(error="bits는 정수여야 합니다."), 400
    if bits not in (1024, 2048):
        return jsonify(error="키 크기는 1024 또는 2048만 지원합니다."), 400
    try:
        keystore.generate_rsa_enc(bits)
        return jsonify(ok=True, bits=bits)
    except Exception as e:  # noqa: BLE001
        return jsonify(error=str(e)), 500


@app.route("/api/rsa/keys")
def api_rsa_keys():
    exists = keystore.enc_keys_exist()
    return jsonify(exists=exists, bits=keystore.enc_key_bits() if exists else None)


# ---------- 전자서명 API ----------

@app.route("/api/sign/keygen", methods=["POST"])
def api_sign_keygen():
    data = request.get_json(silent=True) or {}
    algo = data.get("algo", "rsa")
    bits = data.get("bits", 2048)
    if algo not in signing.ALGOS:
        return jsonify(error="알 수 없는 알고리즘입니다."), 400
    if algo == "rsa":
        try:
            bits = int(bits)
        except (TypeError, ValueError):
            return jsonify(error="bits는 정수여야 합니다."), 400
        if bits not in (1024, 2048):
            return jsonify(error="키 크기는 1024 또는 2048만 지원합니다."), 400
    try:
        keystore.generate_sign_keys(algo, bits if algo == "rsa" else 2048)
        return jsonify(ok=True)
    except Exception as e:  # noqa: BLE001
        return jsonify(error=str(e)), 500


@app.route("/api/sign/keys")
def api_sign_keys():
    algo = request.args.get("algo", "rsa")
    exists = keystore.sign_keys_exist(algo)
    bits = keystore.sign_rsa_key_bits() if (exists and algo == "rsa") else None
    return jsonify(exists=exists, bits=bits)


@app.route("/api/sign/sign", methods=["POST"])
def api_sign_sign():
    data = request.get_json(silent=True) or {}
    algo = data.get("algo", "rsa")
    message = data.get("message", "")
    if algo not in signing.ALGOS:
        return jsonify(error="알 수 없는 알고리즘입니다."), 400
    try:
        sig = signing.sign(algo, message.encode("utf-8"))
        return jsonify(signature=base64.b64encode(sig).decode("ascii"))
    except Exception as e:  # noqa: BLE001
        return jsonify(error=str(e)), 400


@app.route("/api/sign/verify", methods=["POST"])
def api_sign_verify():
    data = request.get_json(silent=True) or {}
    algo = data.get("algo", "rsa")
    message = data.get("message", "")
    sig_b64 = data.get("signature", "")
    if algo not in signing.ALGOS:
        return jsonify(error="알 수 없는 알고리즘입니다."), 400
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:  # noqa: BLE001
        return jsonify(error="서명이 올바른 base64 형식이 아닙니다."), 400
    try:
        valid = signing.verify(algo, message.encode("utf-8"), sig)
        return jsonify(valid=valid)
    except Exception as e:  # noqa: BLE001
        return jsonify(error=str(e)), 400


if __name__ == "__main__":
    app.run(debug=True, port=5000)
