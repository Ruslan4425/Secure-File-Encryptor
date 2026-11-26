
import pytest
import struct
import stat
import os
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization

import AES as test_As


@pytest.fixture()
def signing_keys_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with patch("getpass.getpass", side_effect=["password1234", "password1234"]):
        test_As.generate_signing_keys()

    plain_file = tmp_path / "secret.txt"
    data = b"Confidential security payload"
    plain_file.write_bytes(data)

    enc_file = tmp_path / "encrypted.enc"
    dec_file = tmp_path / "decrypted.txt"

    return {
        "dir": tmp_path,
        "plain": plain_file,
        "enc": enc_file,
        "dec": dec_file,
        "data": data,
    }


#########################################
# MEMORY CLEANER
#########################################

def test_memory_cleaner():
    password = bytearray(b"password1234")
    test_As.memory_cleaner(password)
    assert password == bytearray(len(password))


def test_memory_cleaner_empty_buffer():
    password = bytearray(b"")
    test_As.memory_cleaner(password)
    assert password == bytearray()


def test_memory_cleaner_invalid_type():
    password = "password123"
    result = test_As.memory_cleaner(password)
    assert result is None


#######################################
# CHUNK NONCE
#######################################

def test_derive_chunk_nonce():
    nonce = os.urandom(test_As.NONCE_SIZE)
    result = test_As.derive_chunk_nonce(nonce, 1)
    assert len(result) == test_As.NONCE_SIZE
    assert isinstance(result, bytes)


def test_derive_chunk_nonce_zero_index():
    nonce = os.urandom(test_As.NONCE_SIZE)
    result = test_As.derive_chunk_nonce(nonce, 0)
    assert result == nonce


def test_derive_chunk_nonce_invalid_index():
    with pytest.raises(TypeError):
        test_As.derive_chunk_nonce(os.urandom(test_As.NONCE_SIZE), "string")


#######################################
# ATOMIC WRITE SECRET
#######################################

def test_atomic_write_secret_success(tmp_path):
    secret_file = tmp_path / "private.key"
    data = b"secretData"

    test_As.atomic_write_secret(secret_file, data)

    assert secret_file.exists()
    assert secret_file.read_bytes() == data


def test_atomic_write_secret_permissions(tmp_path):
    secret_file = tmp_path / "private.key"
    data = b"secretData"

    test_As.atomic_write_secret(secret_file, data)

    assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600


#####################################
# GET PASSWORD BYTEARRAY
#####################################

def test_get_password_bytearray():
    with patch("getpass.getpass", return_value="password1234532"):
        result = test_As.get_password_bytearray("Enter password")

    assert result == bytearray(b"password1234532")
    assert isinstance(result, bytearray)


def test_get_password_bytearray_special_characters():
    password = "&%%&*)DF57734&^*"

    with patch("getpass.getpass", return_value=password):
        result = test_As.get_password_bytearray("Enter password")

    assert result == bytearray(password.encode("utf-8"))


#########################################
# VALIDATE ARGON2 PARAMETERS
#########################################

def test_validate_argon2_params_valid():
    result = test_As.validate_argon2_params(6, 65536, 4)
    assert result is None


def test_validate_argon2_params_invalid():
    with pytest.raises(ValueError):
        test_As.validate_argon2_params(44, 65536, 0)


###########################################
# GENERATE SIGNING KEYS
###########################################

def test_generate_signing_keys_success(signing_keys_env):
    assert Path("signing_private.key").exists()
    assert Path("signing_public.key").exists()


def test_generate_signing_keys_already_exist(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    Path("signing_private.key").write_bytes(b"data")
    Path("signing_public.key").write_bytes(b"data")

    with pytest.raises(FileExistsError):
        test_As.generate_signing_keys()


def test_generate_signing_keys_password_mismatch(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError):
        with patch("getpass.getpass", side_effect=["12345", "456gf"]):
            test_As.generate_signing_keys()


#############################################
# LOAD PRIVATE KEY
#############################################

def test_load_private_key_success(signing_keys_env):
    with patch("getpass.getpass", return_value="password1234"):
        result = test_As.load_private_key()

    public_key = test_As.load_public_key()

    assert result.public_key().public_bytes_raw() == public_key.public_bytes_raw()


def test_load_private_key_insecure_permissions(signing_keys_env, capsys):
    Path("signing_private.key").chmod(0o644)

    with patch("getpass.getpass", return_value="password1234"):
        test_As.load_private_key()

    captured = capsys.readouterr()
    assert "WARNING" in captured.out

    Path("signing_private.key").chmod(0o600)


def test_load_private_key_not_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(FileNotFoundError):
        test_As.load_private_key()


def test_load_private_key_corrupted(signing_keys_env):
    Path("signing_private.key").write_bytes(b"data")

    with patch("getpass.getpass", return_value="password1234"):
        with pytest.raises(ValueError):
            test_As.load_private_key()


###############################################
# LOAD PUBLIC KEY
###############################################

def test_load_public_key_success(signing_keys_env):
    result = test_As.load_public_key()

    actual_pem = result.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    assert actual_pem == Path("signing_public.key").read_bytes()


################################################
# ENCRYPT FILE
################################################

def test_encrypt_file_success(signing_keys_env):
    env = signing_keys_env

    with patch("getpass.getpass", return_value="password1234"):
        test_As.encrypt_file(
            str(env["plain"]),
            str(env["enc"]),
            bytearray(b"file_password")
        )

    assert env["enc"].is_file()
    assert env["data"] not in env["enc"].read_bytes()
    assert env["enc"].read_bytes().startswith(test_As.MAGIC)


def test_encrypt_empty_file(signing_keys_env):
    env = signing_keys_env

    empty_file = env["dir"] / "empty.txt"
    encrypted_file = env["dir"] / "empty.enc"

    empty_file.write_bytes(b"")

    with patch("getpass.getpass", return_value="password1234"):
        test_As.encrypt_file(
            str(empty_file),
            str(encrypted_file),
            bytearray(b"file password")
        )

    assert encrypted_file.exists()
    assert encrypted_file.stat().st_size > test_As.HEADER_SIZE

    encrypted_data = encrypted_file.read_bytes()

    chunk_length = struct.unpack(
        ">I",
        encrypted_data[test_As.HEADER_SIZE:test_As.HEADER_SIZE + 4]
    )[0]

    assert chunk_length == test_As.GCM_TAG_SIZE


def test_encrypt_file_same_input_output(signing_keys_env):
    env = signing_keys_env

    with pytest.raises(ValueError):
        test_As.encrypt_file(
            str(env["plain"]),
            str(env["plain"]),
            bytearray(b"file password")
        )


def test_encrypt_file_input_not_found(signing_keys_env):
    env = signing_keys_env

    with pytest.raises(FileNotFoundError):
        test_As.encrypt_file(
            "not_exists.txt",
            str(env["enc"]),
            bytearray(b"file password")
        )


def test_encrypt_file_two_chunks(signing_keys_env):
    env = signing_keys_env

    data = os.urandom(test_As.CHUNK_SIZE + 1)
    env["plain"].write_bytes(data)

    with patch("getpass.getpass", return_value="password1234"):
        test_As.encrypt_file(
            str(env["plain"]),
            str(env["enc"]),
            bytearray(b"file password")
        )

    assert env["enc"].exists()


def test_encrypt_file_randomness(signing_keys_env):
    env = signing_keys_env

    encrypted1 = env["dir"] / "first.enc"
    encrypted2 = env["dir"] / "second.enc"

    password = bytearray(b"file_password")

    with patch("getpass.getpass", return_value="password1234"):
        test_As.encrypt_file(
            str(env["plain"]),
            str(encrypted1),
            password
        )

        test_As.encrypt_file(
            str(env["plain"]),
            str(encrypted2),
            password
        )

    assert encrypted1.read_bytes() != encrypted2.read_bytes()


def test_encrypt_file_one_byte(signing_keys_env):
    env = signing_keys_env

    env["plain"].write_bytes(b"A")

    with patch("getpass.getpass", return_value="password1234"):
        test_As.encrypt_file(
            str(env["plain"]),
            str(env["enc"]),
            bytearray(b"file password")
        )

    assert env["enc"].exists()


def test_encrypt_file_one_chunk(signing_keys_env):
    env = signing_keys_env

    data = os.urandom(test_As.CHUNK_SIZE)
    env["plain"].write_bytes(data)

    with patch("getpass.getpass", return_value="password1234"):
        test_As.encrypt_file(
            str(env["plain"]),
            str(env["enc"]),
            bytearray(b"file password")
        )

    assert env["enc"].exists()


#############################
# DECRYPT FILE
#############################

def create_encrypted_file(env):
    with patch("getpass.getpass", return_value="password1234"):
        test_As.encrypt_file(
            str(env["plain"]),
            str(env["enc"]),
            bytearray(b"file password")
        )


def test_decrypt_file_success(signing_keys_env):
    env = signing_keys_env
    create_encrypted_file(env)

    with patch("getpass.getpass", return_value="file password"):
        test_As.decrypt_file(
            str(env["enc"]),
            str(env["dec"])
        )

    assert env["dec"].exists()
    assert env["dec"].read_bytes() == env["data"]


def test_decrypt_file_wrong_password(signing_keys_env):
    env = signing_keys_env
    create_encrypted_file(env)

    with patch("getpass.getpass", return_value="wrong password"):
        with pytest.raises(ValueError, match="Decryption failed"):
            test_As.decrypt_file(
                str(env["enc"]),
                str(env["dec"])
            )


def test_decrypt_file_invalid_signature(signing_keys_env):
    env = signing_keys_env
    create_encrypted_file(env)

    data = bytearray(env["enc"].read_bytes())
    data[-1] ^= 0x01
    env["enc"].write_bytes(data)

    with patch("getpass.getpass") as password_mock:
        with pytest.raises(ValueError, match="SIGNATURE IS INVALID"):
            test_As.decrypt_file(
                str(env["enc"]),
                str(env["dec"])
            )

    password_mock.assert_not_called()


def test_decrypt_file_wrong_public_key(signing_keys_env):
    env = signing_keys_env
    create_encrypted_file(env)

    wrong_private_key = test_As.Ed25519PrivateKey.generate()
    wrong_public_key = wrong_private_key.public_key()

    public_bytes = wrong_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    Path("signing_public.key").write_bytes(public_bytes)

    with patch("getpass.getpass") as password_mock:
        with pytest.raises(ValueError, match="SIGNATURE IS INVALID"):
            test_As.decrypt_file(
                str(env["enc"]),
                str(env["dec"])
            )

    password_mock.assert_not_called()


def test_decrypt_file_truncated_chunk(signing_keys_env):
    env = signing_keys_env
    create_encrypted_file(env)

    data = bytearray(env["enc"].read_bytes())

    del data[-(test_As.ED25519_SIG_SIZE + 5):-test_As.ED25519_SIG_SIZE]

    env["enc"].write_bytes(data)

    with pytest.raises(ValueError, match="File is truncated or corrupted"):
        test_As.decrypt_file(
            str(env["enc"]),
            str(env["dec"])
        )

    assert not env["dec"].exists()


def test_decrypt_file_multiple_chunks(signing_keys_env):

    env = signing_keys_env

    data = os.urandom(test_As.CHUNK_SIZE * 2 + 100)

    env["plain"].write_bytes(data)
    create_encrypted_file(env)

    with patch("getpass.getpass", return_value="file password"):
        test_As.decrypt_file(
            str(env["enc"]),
            str(env["dec"])
        )

    assert env["dec"].read_bytes() == data


def test_decrypt_file_not_found(signing_keys_env):

    env = signing_keys_env

    create_encrypted_file(env)

    with pytest.raises(FileNotFoundError):
        test_As.decrypt_file(
            str(env["dir"] / "missing.enc"),
            str(env["dec"])
        )


def test_decrypt_file_empty_input(signing_keys_env):

    env = signing_keys_env

    env["enc"].write_bytes(b"")

    with pytest.raises(ValueError):
        test_As.decrypt_file(
            str(env["enc"]),
            str(env["dec"])
        )
    assert not env["dec"].exists()


def test_decrypt_file_output_already_exists(signing_keys_env):

    env = signing_keys_env

    create_encrypted_file(env)

    env["dec"].write_bytes(b"data")

    with patch("getpass.getpass", return_value="file password"):
        test_As.decrypt_file(
            str(env["enc"]),
            str(env["dec"])
        )

    assert env["dec"].read_bytes() == env["data"]


def test_decrypt_file_corrupted_chunk_with_valid_signature(signing_keys_env):

    env = signing_keys_env

    create_encrypted_file(env)

    data = bytearray(env["enc"].read_bytes())

    chunk_start = test_As.HEADER_SIZE + 4
    data[chunk_start] ^= 0x01

    with patch("getpass.getpass", return_value="password1234"):
        private_key = test_As.load_private_key()

    hasher = test_As.hashlib.blake2b(
        digest_size=test_As.BLAKE2B_DIGEST_SIZE
    )
    
    hasher.update(data[:-test_As.ED25519_SIG_SIZE])

    signature = private_key.sign(hasher.digest())

    data[-test_As.ED25519_SIG_SIZE:] = signature
    env["enc"].write_bytes(data)

    with patch("getpass.getpass", return_value="file password"):
        with pytest.raises(ValueError, match="Decryption failed"):
            test_As.decrypt_file(
                str(env["enc"]),
                str(env["dec"])
            )
    assert not env["dec"].exists()


def test_decrypt_file_invalid_time_cost(signing_keys_env):
    env = signing_keys_env
    create_encrypted_file(env)

    data = bytearray(env["enc"].read_bytes())

    struct.pack_into(">I", data, 5, 100)
    
    env["enc"].write_bytes(data)

    with pytest.raises(ValueError, match="Time Cost"):
        test_As.decrypt_file(
            str(env["enc"]),
            str(env["dec"])
        )


def test_decrypt_file_invalid_magic(signing_keys_env):

    env = signing_keys_env
    create_encrypted_file(env)

    data = bytearray(env["enc"].read_bytes())

    data[0:4] = b"xxxx"

    env["enc"].write_bytes(data)

    with pytest.raises(ValueError, match="MAGIC"):
        test_As.decrypt_file(
            str(env["enc"]),
            str(env["dec"])
        )
