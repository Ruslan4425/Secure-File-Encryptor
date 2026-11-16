import os
import stat
import base64
import json
import argparse
import getpass
from pathlib import Path

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    BestAvailableEncryption,
    load_pem_private_key,
    load_pem_public_key
)
from cryptography.exceptions import InvalidSignature, InvalidTag

VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
GCM_TAG_SIZE = 16
ED25519_SIG_SIZE = 64

ARGON_TIME_COST = 3
ARGON_MEMORY_COST = 65536
ARGON_PARALLELISM = 4

PRIVATE_KEY_FILE = "signing_private.key"
PUBLIC_KEY_FILE = "signing_public.key"


def encode64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode64(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def canonical_json(data: dict) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST,
        parallelism=ARGON_PARALLELISM,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def generate_signing_keys():
    priv_path = Path(PRIVATE_KEY_FILE)
    pub_path = Path(PUBLIC_KEY_FILE)

    if priv_path.exists() or pub_path.exists():
        raise FileExistsError("Ключи уже существуют. Не перезаписывайте их.")

    key_pwd1 = getpass.getpass("Придумайте пароль для защиты приватного ключа подписи Ed25519: ")
    key_pwd2 = getpass.getpass("Повторите пароль: ")

    if not key_pwd1 or key_pwd1 != key_pwd2:
        raise ValueError("Пароли для ключа не совпадают или пустые") 

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(key_pwd1.encode("utf-8")),
    )

    public_bytes = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(private_bytes)
    pub_path.write_bytes(public_bytes)

    if os.name == "posix":
        os.chmod(priv_path, 0o600)

    print("[+] Ключи успешно созданы:")
    print(f"    Приватный ключ: {PRIVATE_KEY_FILE}")
    print(f"    Публичный ключ: {PUBLIC_KEY_FILE}")


def load_private_key() -> Ed25519PrivateKey:
    priv_path = Path(PRIVATE_KEY_FILE)
    if not priv_path.is_file():
        raise FileNotFoundError(
            f"Приватный ключ '{PRIVATE_KEY_FILE}' не найден. Сначала выполните команду keygen."
        )
    key_pwd = getpass.getpass("Введите пароль от приватного ключа подписи")

    if os.name == "posix":
        mode = stat.S_IMODE(priv_path.stat().st_mode)
        if mode != 0o600:
            print(
                f"[!] ПРЕДУПРЕЖДЕНИЕ: небезопасные права доступа ({oct(mode)}) для {PRIVATE_KEY_FILE}. Рекомендуется 0o600."
            )

    key_data = priv_path.read_bytes()
    return load_pem_private_key(key_data,password=key_pwd.encode("utf-8"))


def load_public_key() -> Ed25519PublicKey:
    pub_path = Path(PUBLIC_KEY_FILE)
    if not pub_path.is_file():
        raise FileNotFoundError(f"Публичный ключ '{PUBLIC_KEY_FILE}' не найден.")

    return load_pem_public_key(pub_path.read_bytes()) 


def encrypt_file(input_file: str, output_file: str, password: str):
    input_path = Path(input_file)
    output_path = Path(output_file)

    if not input_path.is_file():
        raise FileNotFoundError(f"Исходный файл '{input_file}' не найден.")

    if input_path.resolve() == output_path.resolve():
        raise ValueError("Входной и выходной файлы не могут совпадать.")

    print("[*] Чтение исходного файла...")
    plain_text = input_path.read_bytes()

    print("[*] Генерация Salt и Nonce...")
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    print("[*] Получение ключа через Argon2id...")
    aes_key = derive_key(password, salt)

    header = {
        "version": VERSION,
        "algorithm": "AES-256-GCM",
        "kdf": "Argon2id",
        "argon_time": ARGON_TIME_COST,
        "argon_memory": ARGON_MEMORY_COST,
        "argon_parallelism": ARGON_PARALLELISM,
        "salt": encode64(salt),
        "nonce": encode64(nonce),
    }

    aad = canonical_json(header)

    print("[*] Шифрование AES-256-GCM...")
    aes = AESGCM(aes_key)
    cipher_text = aes.encrypt(nonce, plain_text, aad)

    print("[*] Создание цифровой подписи Ed25519...")
    private_key = load_private_key()

    signed_data = {
        **header,
        "cipher_text": encode64(cipher_text),
    }

    signature = private_key.sign(canonical_json(signed_data))

    payload = {
        **signed_data,
        "signature": encode64(signature),
    }

    output_path.write_text(
        json.dumps(payload, indent=4),
        encoding="utf-8",
    )

    print(f"[+] Шифрование завершено. Результат сохранен в '{output_file}'.")

def decrypt_file(input_file: str, output_file: str, password: str):
    encrypted_path = Path(input_file)
    output_path = Path(output_file)

    if not encrypted_path.is_file():
        raise FileNotFoundError(f"Зашифрованный файл '{input_file}' не найден.")

    if encrypted_path.resolve() == output_path.resolve():
        raise ValueError("Входной и выходной файлы не могут совпадать.")

    print("[*] Чтение зашифрованного контейнера...")
    try:
        payload = json.loads(encrypted_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raise ValueError("Файл поврежден или имеет неверный формат JSON.")

    required_fields = {
        "version",
        "algorithm",
        "kdf",
        "argon_time",
        "argon_memory",
        "argon_parallelism",
        "salt",
        "nonce",
        "cipher_text",
        "signature",
    }
    if not required_fields.issubset(payload.keys()):
        raise ValueError("В контейнере отсутствуют обязательные поля заголовка.")

    if payload["version"] != VERSION:
        raise ValueError(f"Неподдерживаемая версия формата: {payload['version']}.")

    if payload["algorithm"] != "AES-256-GCM":
        raise ValueError("Неподдерживаемый алгоритм шифрования.")

    if payload["kdf"] != "Argon2id":
        raise ValueError("Неподдерживаемый алгоритм KDF.")

    if (
        payload["argon_time"] != ARGON_TIME_COST
        or payload["argon_memory"] != ARGON_MEMORY_COST
        or payload["argon_parallelism"] != ARGON_PARALLELISM
    ):
        raise ValueError("Некорректные параметры Argon2id.")

    header = {
        "version": payload["version"],
        "algorithm": payload["algorithm"],
        "kdf": payload["kdf"],
        "argon_time": payload["argon_time"],
        "argon_memory": payload["argon_memory"],
        "argon_parallelism": payload["argon_parallelism"],
        "salt": payload["salt"],
        "nonce": payload["nonce"],
    }

    cipher_text = decode64(payload["cipher_text"])
    signature = decode64(payload["signature"])
    salt = decode64(payload["salt"])
    nonce = decode64(payload["nonce"])

    if len(signature) != ED25519_SIG_SIZE:
        raise ValueError("Неправильная длина цифровой подписи Ed25519.")

    if len(salt) != SALT_SIZE:
        raise ValueError("Некорректная длина Salt.")

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Некорректная длина Nonce.")

    if len(cipher_text) < GCM_TAG_SIZE:
        raise ValueError("Некорректный размер шифротекста.")

    print("[*] Проверка цифровой подписи Ed25519...")
    public_key = load_public_key()

    signed_data = {
        **header,
        "cipher_text": payload["cipher_text"],
    }

    try:
        public_key.verify(signature, canonical_json(signed_data))
    except InvalidSignature:
        raise ValueError("Цифровая подпись недействительна! Файл был изменен или подделан.")

    print("[+] Цифровая подпись подтверждена.")

    print("[*] Получение ключа через Argon2id...")
    aes_key = derive_key(password, salt)

    print("[*] Расшифровка данных...")
    aes = AESGCM(aes_key)
    aad = canonical_json(header)

    try:
        plaintext = aes.decrypt(nonce, cipher_text, aad)
    except InvalidTag:
        raise ValueError("Ошибка аутентификации GCM: неверный пароль или данные повреждены.")

    output_path.write_bytes(plaintext)
    print(f"[+] Расшифровка завершена. Файл сохранен в '{output_file}'.")


def main():
    parser = argparse.ArgumentParser(
        description="Утилита шифрования файлов (AES-256-GCM + Argon2id + Ed25519)"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("keygen", help="Создать пару ключей подписи Ed25519")

    encrypt_parser = subparsers.add_parser("encrypt", help="Зашифровать и подписать файл")
    encrypt_parser.add_argument("input", help="Путь к исходному файлу")
    encrypt_parser.add_argument("output", help="Путь для сохранения зашифрованного файла")

    decrypt_parser = subparsers.add_parser("decrypt", help="Проверить подпись и расшифровать файл")
    decrypt_parser.add_argument("input", help="Путь к зашифрованному файлу")
    decrypt_parser.add_argument("output", help="Путь для сохранения расшифрованного файла")

    args = parser.parse_args()

    try:
        if args.command == "keygen":
            generate_signing_keys()
        elif args.command == "encrypt":
            pwd1 = getpass.getpass("Введите пароль для шифрования: ")
            pwd2 = getpass.getpass("Повторите пароль: ")
            if not pwd1:
                raise ValueError("Пароль не может быть пустым.")
            if pwd1 != pwd2:
                raise ValueError("Введенные пароли не совпадают.")
            encrypt_file(args.input, args.output, pwd1)
        elif args.command == "decrypt":
            pwd = getpass.getpass("Введите пароль для расшифровки: ")
            if not pwd:
                raise ValueError("Пароль не может быть пустым.")
            decrypt_file(args.input, args.output, pwd)
    except Exception as e:
        print(f"[ОШИБКА] {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
