import json
import base64
import pytest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature, InvalidTag

import AES


@pytest.fixture
def crypto_env(tmp_path: Path, monkeypatch):
    """Подготавливает изолированное окружение с ключами и тестовым файлом."""
    # Генерируем тестовую пару ключей Ed25519 в памяти (без записи на диск и запросов пароля)
    priv_key = Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    # Подменяем функции загрузки ключей и ускоряем Argon2id для быстрых тестов
    monkeypatch.setattr(AES, "load_private_key", lambda: priv_key)
    monkeypatch.setattr(AES, "load_public_key", lambda: pub_key)
    monkeypatch.setattr(AES, "ARGON_TIME_COST", 1)
    monkeypatch.setattr(AES, "ARGON_MEMORY_COST", 1024)
    monkeypatch.setattr(AES, "ARGON_PARALLELISM", 1)

    plain_file = tmp_path / "secret.txt"
    original_data = b"Confidential security payload 12345!"
    plain_file.write_bytes(original_data)

    enc_file = tmp_path / "secret.enc.json"
    dec_file = tmp_path / "decrypted.txt"
    password = "StrongFilePassword!2026"

    AES.encrypt_file(str(plain_file), str(enc_file), password)

    return {
        "tmp_path": tmp_path,
        "priv_key": priv_key,
        "pub_key": pub_key,
        "original_data": original_data,
        "enc_file": enc_file,
        "dec_file": dec_file,
        "password": password,
    }


def test_happy_path_and_empty_file(crypto_env):
    """Базовая проверка: успешная расшифровка и работа с пустым файлом (0 байт)."""
    env = crypto_env
    AES.decrypt_file(str(env["enc_file"]), str(env["dec_file"]), env["password"])
    assert env["dec_file"].read_bytes() == env["original_data"]

    # Проверка граничного случая: пустой файл
    empty_in = env["tmp_path"] / "empty.txt"
    empty_in.write_bytes(b"")
    empty_enc = env["tmp_path"] / "empty.enc.json"
    empty_dec = env["tmp_path"] / "empty_dec.txt"

    AES.encrypt_file(str(empty_in), str(empty_enc), env["password"])
    AES.decrypt_file(str(empty_enc), str(empty_dec), env["password"])
    assert empty_dec.read_bytes() == b""


def test_bit_flip_in_ciphertext(crypto_env):
    """Атака: изменение 1 бита в шифротексте (проверка защиты Encrypt-then-Sign)."""
    env = crypto_env
    payload = json.loads(env["enc_file"].read_text(encoding="utf-8"))

    # Декодируем шифротекст, инвертируем 1 бит и кодируем обратно
    ct = bytearray(base64.b64decode(payload["cipher_text"]))
    ct[0] ^= 0x01
    payload["cipher_text"] = base64.b64encode(bytes(ct)).decode("ascii")

    tampered = env["tmp_path"] / "tampered_ct.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises((InvalidSignature, ValueError)):
        AES.decrypt_file(str(tampered), str(env["dec_file"]), env["password"])

    assert not env["dec_file"].exists()


def test_aad_header_tampering(crypto_env):
    """Атака: подмена метаданных заголовка, даже если злоумышленник переподписал файл."""
    env = crypto_env
    payload = json.loads(env["enc_file"].read_text(encoding="utf-8"))

    # Злоумышленник меняет nonce и пересчитывает подпись Ed25519 своим (или украденным) ключом
    fake_nonce = bytearray(base64.b64decode(payload["nonce"]))
    fake_nonce[0] ^= 0xFF
    payload["nonce"] = base64.b64encode(bytes(fake_nonce)).decode("ascii")

    signed_data = {k: v for k, v in payload.items() if k != "signature"}
    new_sig = env["priv_key"].sign(AES.canonical_json(signed_data))
    payload["signature"] = base64.b64encode(new_sig).decode("ascii")

    tampered = env["tmp_path"] / "tampered_aad.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")

    # Расшифровка должна упасть на уровне AES-GCM (InvalidTag), так как заголовок защищен AAD
    with pytest.raises((InvalidTag, ValueError)):
        AES.decrypt_file(str(tampered), str(env["dec_file"]), env["password"])


def test_malformed_json_and_missing_fields(crypto_env):
    """Атака: поврежденный JSON или удаление обязательного поля из контейнера."""
    env = crypto_env

    # 1. Битый синтаксис JSON
    broken_json = env["tmp_path"] / "broken.json"
    broken_json.write_text("{corrupted_json: [1, 2", encoding="utf-8")
    with pytest.raises(ValueError, match="неверный формат JSON"):
        AES.decrypt_file(str(broken_json), str(env["dec_file"]), env["password"])

    # 2. Удаление поля salt
    payload = json.loads(env["enc_file"].read_text(encoding="utf-8"))
    del payload["salt"]
    missing_field_file = env["tmp_path"] / "missing_field.json"
    missing_field_file.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="отсутствуют обязательные поля"):
        AES.decrypt_file(str(missing_field_file), str(env["dec_file"]), env["password"])


def test_downgrade_and_dos_argon_params(crypto_env):
    """Атака: попытка подсунуть заниженные или завышенные параметры Argon2id."""
    env = crypto_env
    payload = json.loads(env["enc_file"].read_text(encoding="utf-8"))

    # Злоумышленник ставит memory_cost = 200 ГБ (DoS-атака)
    payload["argon_memory"] = 200_000_000
    tampered = env["tmp_path"] / "dos_argon.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="Некорректные параметры Argon2id"):
        AES.decrypt_file(str(tampered), str(env["dec_file"]), env["password"])


def test_wrong_password_and_wrong_key(crypto_env, monkeypatch):
    """Атака: расшифровка неверным паролем или чужим публичным ключом."""
    env = crypto_env

    # 1. Неверный пароль (подпись Ed25519 пройдет, но AES-GCM отвергнет ключ)
    with pytest.raises((InvalidTag, ValueError)):
        AES.decrypt_file(str(env["enc_file"]), str(env["dec_file"]), "WrongPassword!")

    # 2. Чужой публичный ключ (проверка подписи упадет до расшифровки)
    wrong_pub_key = Ed25519PrivateKey.generate().public_key()
    monkeypatch.setattr(AES, "load_public_key", lambda: wrong_pub_key)

    with pytest.raises((InvalidSignature, ValueError)):
        AES.decrypt_file(str(env["enc_file"]), str(env["dec_file"]), env["password"])
