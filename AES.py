import os
import stat
import argparse
import getpass
import ctypes
import struct
import hashlib

#Delete
import base64
import json

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

MAGIC = b"AESS"
CHUNK_SIZE = 64 * 1024 # 64 KB blocks
HEADER_FORMAT = ">4sBIII16s12s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) # 45 bytes
BLAKE2B_DIGEST_SIZE = 32

MIN_TIME_COST = 2
MAX_TIME_COST = 10
MIN_MEMORY_COST = 32768
MAX_MEMORY_COST = 1048576
MIN_PARALLELISM = 1
MAX_PARALLELISM = 16

VERSION = 2
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


def memory_cleaner(buffer: bytearray) -> None:
    if not isinstance(buffer,bytearray) or len(buffer) == 0:
        return

    ptr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))

    ctypes.memset(ptr, 0, len(buffer))

def derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:

    base_int = int.from_bytes(base_nonce, byteorder= "big")
    chunk_int = base_int ^ chunk_index
    return chunk_int.to_bytes(NONCE_SIZE, byteorder= "big")

def atomic_write_secret(patch: Path, data: bytes) -> None:

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(patch, flags, 0o600)

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        if patch.exists():
            patch.unlink()
        raise

def get_password_bytearray(password: str) -> bytearray:

    pasword_str = getpass.getpass(password)
    return bytearray(pasword_str.encode("utf-8"))

def validate_parametr_Argon2(time_cost: int, memory_cost: int, parallelism_cost: int) -> None:

    if time_cost < MIN_TIME_COST or time_cost > MAX_TIME_COST:
        raise ValueError("Недопустимый Time")
    if memory_cost < MIN_MEMORY_COST or memory_cost > MAX_MEMORY_COST:
        raise ValueError("Недопустимое значение Memory")
    if parallelism_cost < MIN_PARALLELISM or parallelism_cost > MAX_PARALLELISM:
        raise ValueError("Недопустимое значение Parallelism")

def derive_key(password: bytearray,
               salt: bytes, time_cost: int = ARGON_TIME_COST,
               memory_cost: int = ARGON_MEMORY_COST,
               parallelism_cost: int = ARGON_PARALLELISM) -> bytearray:
               
    return bytearray( hash_secret_raw(
        secret=bytes(password),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism_cost,
        hash_len=KEY_SIZE,
        type=Type.ID,)
        )


def generate_signing_keys():
    priv_path = Path(PRIVATE_KEY_FILE)
    pub_path = Path(PUBLIC_KEY_FILE)

    if priv_path.exists() or pub_path.exists():
        raise FileExistsError("Ключи уже существуют. Не перезаписывайте их.")

    key_pwd1 = get_password_bytearray("Придумайте пароль для защиты приватного ключа подписи Ed25519: ")
    key_pwd2 = get_password_bytearray("Повторите пароль: ")

    try:
       if len(key_pwd1) == 0  or key_pwd1 != key_pwd2:
        raise ValueError("Пароли для ключа не совпадают или пустые") 

       private_key = Ed25519PrivateKey.generate()
       public_key = private_key.public_key()

       private_bytes = private_key.private_bytes(
           encoding=Encoding.PEM,
           format=PrivateFormat.PKCS8,
           encryption_algorithm=BestAvailableEncryption(bytes(key_pwd1)),
       )

       public_bytes = public_key.public_bytes(
           encoding=Encoding.PEM,
           format=PublicFormat.SubjectPublicKeyInfo,
       )

       atomic_write_secret(priv_path, private_bytes)
       pub_path.write_bytes(public_bytes)

    finally:
        memory_cleaner(key_pwd1)
        memory_cleaner(key_pwd2)

    print("[+] Ключи успешно созданы:")
    print(f"    Приватный ключ: {PRIVATE_KEY_FILE}")
    print(f"    Публичный ключ: {PUBLIC_KEY_FILE}")


def load_private_key() -> Ed25519PrivateKey:
    priv_path = Path(PRIVATE_KEY_FILE)
    if not priv_path.is_file():
        raise FileNotFoundError(
            f"Приватный ключ '{PRIVATE_KEY_FILE}' не найден. Сначала выполните команду keygen."
        )

    if os.name == "posix":
        mode = stat.S_IMODE(priv_path.stat().st_mode)
        if mode != 0o600:
            print(
                f"[!] ПРЕДУПРЕЖДЕНИЕ: небезопасные права доступа ({oct(mode)}) для {PRIVATE_KEY_FILE}. Рекомендуется 0o600."
            )

    key_pwd = get_password_bytearray("Введите пароль от приватного ключа подписи")
    try:
        key_data = priv_path.read_bytes()
        return load_pem_private_key(key_data,password=bytes(key_pwd))
    finally:
        memory_cleaner(key_pwd)

def load_public_key() -> Ed25519PublicKey:
    pub_path = Path(PUBLIC_KEY_FILE)
    if not pub_path.is_file():
        raise FileNotFoundError(f"Публичный ключ '{PUBLIC_KEY_FILE}' не найден.")

    return load_pem_public_key(pub_path.read_bytes()) 


def encrypt_file(input_file: str, output_file: str, password: bytearray):
    input_path = Path(input_file)
    output_path = Path(output_file)
    tmp_patch = output_path.with_suffix(output_path.suffix + ".tmp")

    if not input_path.is_file():
        raise FileNotFoundError(f"Исходный файл '{input_file}' не найден.")

    if input_path.resolve() == output_path.resolve():
        raise ValueError("Входной и выходной файлы не могут совпадать.")

    print("[*] Генерация Salt и Nonce...")
    salt = os.urandom(SALT_SIZE)
    base_nonce = os.urandom(NONCE_SIZE)
    private_key = load_private_key()

    aes_key = None

    try:
        aes_key = derive_key(password, salt)
        aes = AESGCM(bytes(aes_key))

        header = struct.pack(
            HEADER_FORMAT,
            MAGIC,
            VERSION,
            ARGON_TIME_COST,
            ARGON_MEMORY_COST,
            ARGON_PARALLELISM,
            salt,
            base_nonce,   
        )
        hasher = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
        hasher.update(header)

        with open(input_path, "rb") as f_in, open(tmp_patch, "wb") as f_out:
            f_out.write(header)

            chunk_index = 0

            while True:
                chunk = f_in.read(CHUNK_SIZE)
                is_last = len(f_in.peek(1)) == 0

                chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index)
                aad = header + struct.pack(">Q?", chunk_index, is_last)
                cipher_text = aes.encrypt(chunk_nonce, chunk, aad)

                lenght_prefix = struct.pack(">I", len(cipher_text))

                hasher.update(lenght_prefix)
                hasher.update(cipher_text)

                f_out.write(lenght_prefix)
                f_out.write(cipher_text)

                chunk_index += 1

                if is_last:
                    break

            signature = private_key.sign(hasher.digest())
            f_out.write(signature)
            f_out.flush()
            os.fsync(f_out.fileno())
            
        os.replace(tmp_patch, output_path)

    except Exception:
        if tmp_patch.exists():
            tmp_patch.unlink()
        raise
    finally:
        if aes_key is not None:
            memory_cleaner(aes_key)
    
    print(f"[+] Шифрование завершено. Результат сохранен в '{output_file}'.")

def decrypt_file(input_file: str, output_file: str, password: str):
    encrypted_path = Path(input_file)
    output_path = Path(output_file)

    if not encrypted_path.exists:
        raise ValueError("Файл не найден")
    if encrypted_path.resolve() == output_path.resolve():
        raise ValueError("Файлы не должны совпадать")
    
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
            pwd1 = get_password_bytearray("Введите пароль для шифрования: ")
            pwd2 = get_password_bytearray("Повторите пароль: ")
            try:
              if len(pwd1) == 0:
                  raise ValueError("Пароль не может быть пустым.")
              if pwd1 != pwd2:
                  raise ValueError("Введенные пароли не совпадают.")
              encrypt_file(args.input, args.output, pwd1)
            finally:
                memory_cleaner(pwd1)
                memory_cleaner(pwd2)
        elif args.command == "decrypt":
            pwd = get_password_bytearray("Введите пароль для расшифровки: ")
            try:
              if len(pwd) == 0:
                  raise ValueError("Пароль не может быть пустым.")
              decrypt_file(args.input, args.output, pwd)
            finally:
                memory_cleaner(pwd)
    except Exception as e:
        print(f"[ОШИБКА] {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
