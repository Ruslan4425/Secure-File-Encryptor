import os
import stat
import argparse
import getpass
import ctypes
import struct
import hashlib
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
    load_pem_public_key,
)
from cryptography.exceptions import InvalidSignature, InvalidTag

MAGIC = b"AESS"
VERSION = 2
CHUNK_SIZE = 64 * 1024  # 64 KB
HEADER_FORMAT = ">4sBIII16s12s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 45 bytes

BLAKE2B_DIGEST_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
GCM_TAG_SIZE = 16
ED25519_SIG_SIZE = 64

# --- ПАРАМЕТРЫ ARGON2ID ---
MIN_TIME_COST = 2
MAX_TIME_COST = 10
MIN_MEMORY_COST = 32768
MAX_MEMORY_COST = 1048576
MIN_PARALLELISM = 1
MAX_PARALLELISM = 16

ARGON_TIME_COST = 3
ARGON_MEMORY_COST = 65536
ARGON_PARALLELISM = 4

PRIVATE_KEY_FILE = "signing_private.key"
PUBLIC_KEY_FILE = "signing_public.key"


# ==========================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И БЕЗОПАСНОСТЬ
# ==========================================

def memory_cleaner(buffer: bytearray) -> None:
    """Обнуляет содержимое bytearray в оперативной памяти."""
    if not isinstance(buffer, bytearray) or len(buffer) == 0:
        return
    ptr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
    ctypes.memset(ptr, 0, len(buffer))


def derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """Генерирует уникальный Nonce для каждого блока на основе базового Nonce и индекса."""
    base_int = int.from_bytes(base_nonce, byteorder="big")
    chunk_int = base_int ^ chunk_index
    return chunk_int.to_bytes(NONCE_SIZE, byteorder="big")


def atomic_write_secret(path: Path, data: bytes) -> None:
    """Атомарно записывает секретный файл с правами доступа 0o600."""
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        if path.exists():
            path.unlink()
        raise


def get_password_bytearray(prompt: str) -> bytearray:
    """Безопасно запрашивает пароль и возвращает его как изменяемый bytearray."""
    password_str = getpass.getpass(prompt)
    return bytearray(password_str.encode("utf-8"))


def validate_argon2_params(time_cost: int, memory_cost: int, parallelism_cost: int) -> None:
    """Проверяет параметры Argon2id из заголовка файла для защиты от DoS."""
    if not (MIN_TIME_COST <= time_cost <= MAX_TIME_COST):
        raise ValueError(f"Недопустимое значение Time Cost: {time_cost}")
    if not (MIN_MEMORY_COST <= memory_cost <= MAX_MEMORY_COST):
        raise ValueError(f"Недопустимое значение Memory Cost: {memory_cost}")
    if not (MIN_PARALLELISM <= parallelism_cost <= MAX_PARALLELISM):
        raise ValueError(f"Недопустимое значение Parallelism: {parallelism_cost}")


def derive_key(
    password: bytearray,
    salt: bytes,
    time_cost: int = ARGON_TIME_COST,
    memory_cost: int = ARGON_MEMORY_COST,
    parallelism_cost: int = ARGON_PARALLELISM,
) -> bytearray:
    return bytearray(
        hash_secret_raw(
            secret=bytes(password),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism_cost,
            hash_len=KEY_SIZE,
            type=Type.ID,
        )
    )

def generate_signing_keys() -> None:

    priv_path = Path(PRIVATE_KEY_FILE)
    pub_path = Path(PUBLIC_KEY_FILE)

    if priv_path.exists() or pub_path.exists():
        raise FileExistsError("Ключи уже существуют. Удалите или переместите старые перед генерацией.")

    key_pwd1 = get_password_bytearray("Придумайте пароль для защиты приватного ключа Ed25519: ")
    key_pwd2 = get_password_bytearray("Повторите пароль: ")

    try:
        if len(key_pwd1) == 0 or key_pwd1 != key_pwd2:
            raise ValueError("Пароли для ключа не совпадают или пустые.")

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
                f"[!] ПРЕДУПРЕЖДЕНИЕ: небезопасные права доступа ({oct(mode)}) для {PRIVATE_KEY_FILE}. "
                "Рекомендуется 0o600."
            )

    key_pwd = get_password_bytearray("Введите пароль от приватного ключа подписи: ")
    try:
        key_data = priv_path.read_bytes()
        return load_pem_private_key(key_data, password=bytes(key_pwd))
    finally:
        memory_cleaner(key_pwd)


def load_public_key() -> Ed25519PublicKey:

    pub_path = Path(PUBLIC_KEY_FILE)
    if not pub_path.is_file():
        raise FileNotFoundError(f"Публичный ключ '{PUBLIC_KEY_FILE}' не найден.")
    return load_pem_public_key(pub_path.read_bytes())

def encrypt_file(input_file: str, output_file: str, password: bytearray) -> None:

    input_path = Path(input_file)
    output_path = Path(output_file)
    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")

    if not input_path.is_file():
        raise FileNotFoundError(f"Исходный файл '{input_file}' не найден.")
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Входной и выходной файлы не могут совпадать.")

    print("[*] Загрузка ключа подписи и генерация параметров...")
    private_key = load_private_key()
    salt = os.urandom(SALT_SIZE)
    base_nonce = os.urandom(NONCE_SIZE)
    aes_key = None

    try:
        print("[*] Выработка ключа шифрования Argon2id...")
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

        print("[*] Шифрование файла...")
        with open(input_path, "rb") as f_in, open(tmp_path, "wb") as f_out:
            f_out.write(header)
            chunk_index = 0

            while True:
                chunk = f_in.read(CHUNK_SIZE)
                is_last = len(f_in.peek(1)) == 0

                chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index)
                aad = header + struct.pack(">Q?", chunk_index, is_last)
                cipher_text = aes.encrypt(chunk_nonce, chunk, aad)

                length_prefix = struct.pack(">I", len(cipher_text))

                hasher.update(length_prefix)
                hasher.update(cipher_text)

                f_out.write(length_prefix)
                f_out.write(cipher_text)

                chunk_index += 1
                if is_last:
                    break

            signature = private_key.sign(hasher.digest())
            f_out.write(signature)
            f_out.flush()
            os.fsync(f_out.fileno())

        os.replace(tmp_path, output_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise
    finally:
        if aes_key is not None:
            memory_cleaner(aes_key)

    print(f"[+] Шифрование и подпись завершены. Результат: '{output_file}'.")

def decrypt_file(input_file: str, output_file: str) -> None:

    encrypted_path = Path(input_file)
    output_path = Path(output_file)
    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")

    if not encrypted_path.is_file():
        raise FileNotFoundError(f"Файл '{input_file}' не найден.")
    if encrypted_path.resolve() == output_path.resolve():
        raise ValueError("Входной и выходной файлы не могут совпадать.")

    file_size = encrypted_path.stat().st_size
    min_size = HEADER_SIZE + 4 + GCM_TAG_SIZE + ED25519_SIG_SIZE
    if file_size < min_size:
        raise ValueError("Файл поврежден или имеет неверный размер.")

    public_key = load_public_key()
    password = None
    aes_key = None

    try:
        with open(encrypted_path, "rb") as f_in:

            print("[*] Проверка цифровой подписи Ed25519...")
            header = f_in.read(HEADER_SIZE)
            magic, version, time_cost, mem_cost, parallelism, salt, base_nonce = struct.unpack(
                HEADER_FORMAT, header
            )

            if magic != MAGIC:
                raise ValueError("Неверный формат файла (несовпадение MAGIC).")
            if version != VERSION:
                raise ValueError(f"Неподдерживаемая версия формата: {version}.")

            validate_argon2_params(time_cost, mem_cost, parallelism)

            hasher = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
            hasher.update(header)

            bytes_left = file_size - HEADER_SIZE - ED25519_SIG_SIZE
            while bytes_left > 0:
                len_bytes = f_in.read(4)
                if len(len_bytes) != 4:
                    raise ValueError("Неожиданный конец файла при чтении длины блока.")
                bytes_left -= 4

                (chunk_len,) = struct.unpack(">I", len_bytes)
                if chunk_len > bytes_left:
                    raise ValueError("Файл обрезан или поврежден (неверная длина блока).")

                cipher_text = f_in.read(chunk_len)
                if len(cipher_text) != chunk_len:
                    raise ValueError("Не удалось прочитать блок целиком.")
                bytes_left -= chunk_len

                hasher.update(len_bytes)
                hasher.update(cipher_text)

            signature = f_in.read(ED25519_SIG_SIZE)
            if len(signature) != ED25519_SIG_SIZE:
                raise ValueError("Подпись отсутствует или повреждена.")

            try:
                public_key.verify(signature, hasher.digest())
            except InvalidSignature:
                raise ValueError("ПОДПИСЬ НЕДЕЙСТВИТЕЛЬНА! Файл изменен или подменен.")

            print("[+] Подпись подтверждена.")
            password = get_password_bytearray("Введите пароль для расшифровки файла: ")
            if len(password) == 0:
                raise ValueError("Пароль не может быть пустым.")

            print("[*] Выработка ключа и расшифровка...")
            aes_key = derive_key(password, salt, time_cost, mem_cost, parallelism)
            aes = AESGCM(bytes(aes_key))

            f_in.seek(HEADER_SIZE)
            bytes_left = file_size - HEADER_SIZE - ED25519_SIG_SIZE
            chunk_index = 0

            with open(tmp_path, "wb") as f_out:
                while bytes_left > 0:
                    (chunk_len,) = struct.unpack(">I", f_in.read(4))
                    bytes_left -= 4

                    cipher_text = f_in.read(chunk_len)
                    bytes_left -= chunk_len

                    is_last = bytes_left == 0
                    chunk_nonce = derive_chunk_nonce(base_nonce, chunk_index)
                    aad = header + struct.pack(">Q?", chunk_index, is_last)

                    try:
                        plain_chunk = aes.decrypt(chunk_nonce, cipher_text, aad)
                    except InvalidTag:
                        raise ValueError("Ошибка расшифровки (неверный пароль или поврежденный блок).")

                    f_out.write(plain_chunk)
                    chunk_index += 1

                f_out.flush()
                os.fsync(f_out.fileno())

        os.replace(tmp_path, output_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise
    finally:
        if password is not None:
            memory_cleaner(password)
        if aes_key is not None:
            memory_cleaner(aes_key)

    print(f"[+] Расшифровка завершена. Результат сохранен в '{output_file}'.")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Утилита для шифрования и подписи файлов (AES-256-GCM + Argon2id + Ed25519)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("keygen", help="Сгенерировать пару ключей подписи Ed25519")

    enc_parser = subparsers.add_parser("encrypt", help="Зашифровать и подписать файл")
    enc_parser.add_argument("input", help="Исходный файл")
    enc_parser.add_argument("output", help="Зашифрованный выходной файл")

    dec_parser = subparsers.add_parser("decrypt", help="Проверить подпись и расшифровать файл")
    dec_parser.add_argument("input", help="Зашифрованный файл")
    dec_parser.add_argument("output", help="Расшифрованный выходной файл")

    args = parser.parse_args()

    try:
        if args.command == "keygen":
            generate_signing_keys()

        elif args.command == "encrypt":
            pwd1 = get_password_bytearray("Придумайте пароль для шифрования файла: ")
            pwd2 = get_password_bytearray("Повторите пароль: ")
            try:
                if len(pwd1) == 0 or pwd1 != pwd2:
                    raise ValueError("Пароли не совпадают или пустые.")
                encrypt_file(args.input, args.output, pwd1)
            finally:
                memory_cleaner(pwd1)
                memory_cleaner(pwd2)

        elif args.command == "decrypt":
            decrypt_file(args.input, args.output)

    except Exception as e:
        print(f"[-] Ошибка: {e}")


if __name__ == "__main__":
    main()

