import pytest
import struct
import stat
import os
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature, InvalidTag

import AES as test_As

#########################################
#                Memory_Cleaner
#########################################
    
def test_memory_cleaner():

    password = bytearray(b"password1234")
    test_As.memory_cleaner(password)
    assert password == bytearray(len(password))

def test_empty_cleaner_memory():
    
    password = bytearray(b"")
    test_As.memory_cleaner(password)
    assert password == bytearray()

def test_memory_cleaner_string():

    password = "password123"
    result = test_As.memory_cleaner(password)
    assert result is None

#######################################
#                chunk_nonce
#######################################

def test_chunk_nonce():

    nonce = os.urandom(test_As.NONCE_SIZE)
    result = test_As.derive_chunk_nonce(nonce,1)
    assert len(result) == test_As.NONCE_SIZE
    assert isinstance(result, bytes)

def test_zero_chunk_nonce():

    nonce = os.urandom(test_As.NONCE_SIZE)
    result = test_As.derive_chunk_nonce(nonce, 0)
    assert result == nonce

def test_string_chunk_nonce():

    with pytest.raises(TypeError):
        test_As.derive_chunk_nonce(os.urandom(test_As.NONCE_SIZE), "string")

#######################################
#               atomic_write_secret
#######################################
#
def test_write_secret_success(tmp_path):

    patch = tmp_path / "private.key"
    data = b"secretData"

    test_As.atomic_write_secret(patch,data)

    assert patch.exists()
    assert patch.read_bytes() == data

def test_permissions_write_secrt(tmp_path):

    patch = tmp_path / "private.key"
    data = b"secretData"

    test_As.atomic_write_secret(patch, data)

    assert stat.S_IMODE(patch.stat().st_mode) == 0o600

#####################################
#           get_password_byterarray
#####################################
#
def test_getpassword():

    with patch("getpass.getpass", return_value ="password1234532"):
         result = test_As.get_password_bytearray("Введите пароль")

    assert result == bytearray(b"password1234532")
    assert isinstance(result, bytearray)

def test_special_characters_getpass():

    password = "&%%&*)DF57734&^*"

    with patch("getpass.getpass", return_value = password):
        result = test_As.get_password_bytearray("Введите пароль")

    assert result == bytearray(password.encode("Utf-8"))

#########################################
#              validate_argon2_params
#########################################

def test_corect_parametr():

    result = test_As.validate_argon2_params(6,65536,4)
    assert result is None

def test_incorect_parametr():

    with pytest.raises(ValueError):
        test_As.validate_argon2_params(44,65536,0)

###########################################
#             generate_signing_key
###########################################

def test_generate_key_success(tmp_path,monkeypatch):

    monkeypatch.chdir(tmp_path)

    with patch("getpass.getpass", side_effect=["233rf1d","233rf1d"]):
        test_As.generate_signing_keys()

    assert Path("signing_private.key").exists()
    assert Path("signing_public.key").exists()

def test_generate_key_already_exists(tmp_path,monkeypatch):

    monkeypatch.chdir(tmp_path)

    Path("signing_private.key").write_bytes(b"data")
    Path("signing_public.key").write_bytes(b"data")

    with pytest.raises(FileExistsError):
        test_As.generate_signing_keys()
