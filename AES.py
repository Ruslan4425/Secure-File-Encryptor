
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

# --- ARGON2ID PARAMETERS ---
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
# HELPER FUNCTIONS AND SECURITY
# ==========================================

def memory_cleaner(buffer: bytearray) -> None:
    """Clears the contents of a bytearray in memory."""
    if not isinstance(buffer, bytearray) or len(buffer) == 0:
        return
    ptr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
    ctypes.memset(ptr, 0, len(buffer))


def derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """Generates a unique nonce for each chunk based on the base nonce and index."""
    base_int = int.from_bytes(base_nonce, byteorder="big")
    chunk_int = base_int ^ chunk_index
    return chunk_int.to_bytes(NONCE_SIZE, byteorder="big")


def atomic_write_secret(path: Path, data: bytes) -> None:
    """Atomically writes a secret file with 0o600 permissions."""
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
    """Securely prompts for a password and returns it as a mutable bytearray."""
    password_str = getpass.getpass(prompt)
    return bytearray(password_str.encode("utf-8"))


def validate_argon2_params(time_cost: int, memory_cost: int, parallelism_cost: int) -> None:
    """Validates Argon2id parameters from the file header to prevent DoS attacks."""
    if not (MIN_TIME_COST <= time_cost <= MAX_TIME_COST):
        raise ValueError(f"Invalid Time Cost value: {time_cost}")
    if not (MIN_MEMORY_COST <= memory_cost <= MAX_MEMORY_COST):
        raise ValueError(f"Invalid Memory Cost value: {memory_cost}")
    if not (MIN_PARALLELISM <= parallelism_cost <= MAX_PARALLELISM):
        raise ValueError(f"Invalid Parallelism value: {parallelism_cost}")


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
        raise FileExistsError("Keys already exist. Delete or move the old ones before generating new keys.")

    key_pwd1 = get_password_bytearray("Enter a password to protect the Ed25519 private key: ")
    key_pwd2 = get_password_bytearray("Repeat password: ")

    try:
        if len(key_pwd1) == 0 or key_pwd1 != key_pwd2:
            raise ValueError("Key passwords do not match or are empty.")

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

    print("[+] Keys successfully generated:")
    print(f"    Private key: {PRIVATE_KEY_FILE}")
    print(f"    Public key: {PUBLIC_KEY_FILE}")


def load_private_key() -> Ed25519PrivateKey:

    priv_path = Path(PRIVATE_KEY_FILE)
    if not priv_path.is_file():
        raise FileNotFoundError(
            f"Private key '{PRIVATE_KEY_FILE}' not found. Run the keygen command first."
        )

    if os.name == "posix":
        mode = stat.S_IMODE(priv_path.stat().st_mode)
        if mode != 0o600:
            print(
                f"[!] WARNING: insecure permissions ({oct(mode)}) for {PRIVATE_KEY_FILE}. "
                "0o600 is recommended."
            )

    key_pwd = get_password_bytearray("Enter the private signing key password: ")
    try:
        key_data = priv_path.read_bytes()
        return load_pem_private_key(key_data, password=bytes(key_pwd))
    finally:
        memory_cleaner(key_pwd)


def load_public_key() -> Ed25519PublicKey:

    pub_path = Path(PUBLIC_KEY_FILE)
    if not pub_path.is_file():
        raise FileNotFoundError(f"Public key '{PUBLIC_KEY_FILE}' not found.")
    return load_pem_public_key(pub_path.read_bytes())

def encrypt_file(input_file: str, output_file: str, password: bytearray) -> None:

    input_path = Path(input_file)
    output_path = Path(output_file)
    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")

    if not input_path.is_file():
        raise FileNotFoundError(f"Input file '{input_file}' not found.")
    if input_path.resolve() == output_path.resolve():
        raise ValueError("Input and output files cannot be the same.")

    print("[*] Loading signing key and generating parameters...")
    private_key = load_private_key()
    salt = os.urandom(SALT_SIZE)
    base_nonce = os.urandom(NONCE_SIZE)
    aes_key = None

    try:
        print("[*] Deriving encryption key using Argon2id...")
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

        print("[*] Encrypting file...")
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

    print(f"[+] Encryption and signing completed. Result: '{output_file}'.")

def decrypt_file(input_file: str, output_file: str) -> None:

    encrypted_path = Path(input_file)
    output_path = Path(output_file)
    tmp_path = output_path.with_suffix(output_path.suffix + ".tmp")

    if not encrypted_path.is_file():
        raise FileNotFoundError(f"File '{input_file}' not found.")
    if encrypted_path.resolve() == output_path.resolve():
        raise ValueError("Input and output files cannot be the same.")

    file_size = encrypted_path.stat().st_size
    min_size = HEADER_SIZE + 4 + GCM_TAG_SIZE + ED25519_SIG_SIZE
    if file_size < min_size:
        raise ValueError("File is corrupted or has an invalid size.")

    public_key = load_public_key()
    password = None
    aes_key = None

    try:
        with open(encrypted_path, "rb") as f_in:

            print("[*] Verifying Ed25519 digital signature...")
            header = f_in.read(HEADER_SIZE)
            magic, version, time_cost, mem_cost, parallelism, salt, base_nonce = struct.unpack(
                HEADER_FORMAT, header
            )

            if magic != MAGIC:
                raise ValueError("Invalid file format (MAGIC mismatch).")
            if version != VERSION:
                raise ValueError(f"Unsupported format version: {version}.")

            validate_argon2_params(time_cost, mem_cost, parallelism)

            hasher = hashlib.blake2b(digest_size=BLAKE2B_DIGEST_SIZE)
            hasher.update(header)

            bytes_left = file_size - HEADER_SIZE - ED25519_SIG_SIZE
            while bytes_left > 0:
                len_bytes = f_in.read(4)
                if len(len_bytes) != 4:
                    raise ValueError("Unexpected end of file while reading chunk length.")
                bytes_left -= 4

                (chunk_len,) = struct.unpack(">I", len_bytes)
                if chunk_len > bytes_left:
                    raise ValueError("File is truncated or corrupted (invalid chunk length).")

                cipher_text = f_in.read(chunk_len)
                if len(cipher_text) != chunk_len:
                    raise ValueError("Failed to read the entire chunk.")
                bytes_left -= chunk_len

                hasher.update(len_bytes)
                hasher.update(cipher_text)

            signature = f_in.read(ED25519_SIG_SIZE)
            if len(signature) != ED25519_SIG_SIZE:
                raise ValueError("Signature is missing or corrupted.")

            try:
                public_key.verify(signature, hasher.digest())
            except InvalidSignature:
                raise ValueError("SIGNATURE IS INVALID! The file has been modified or tampered with.")

            print("[+] Signature verified.")
            password = get_password_bytearray("Enter the password to decrypt the file: ")
            if len(password) == 0:
                raise ValueError("Password cannot be empty.")

            print("[*] Deriving key and decrypting...")
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
                        raise ValueError("Decryption failed (incorrect password or corrupted chunk).")

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

    print(f"[+] Decryption completed. Result saved to '{output_file}'.")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="File encryption and signing utility (AES-256-GCM + Argon2id + Ed25519)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("keygen", help="Generate an Ed25519 signing key pair")

    enc_parser = subparsers.add_parser("encrypt", help="Encrypt and sign a file")
    enc_parser.add_argument("input", help="Input file")
    enc_parser.add_argument("output", help="Encrypted output file")

    dec_parser = subparsers.add_parser("decrypt", help="Verify signature and decrypt a file")
    dec_parser.add_argument("input", help="Encrypted file")
    dec_parser.add_argument("output", help="Decrypted output file")

    args = parser.parse_args()

    try:
        if args.command == "keygen":
            generate_signing_keys()

        elif args.command == "encrypt":
            pwd1 = get_password_bytearray("Enter a password to encrypt the file: ")
            pwd2 = get_password_bytearray("Repeat password: ")
            try:
                if len(pwd1) == 0 or pwd1 != pwd2:
                    raise ValueError("Passwords do not match or are empty.")
                encrypt_file(args.input, args.output, pwd1)
            finally:
                memory_cleaner(pwd1)
                memory_cleaner(pwd2)

        elif args.command == "decrypt":
            decrypt_file(args.input, args.output)

    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    main()
