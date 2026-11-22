<div align="center">

🌐 **Language:** **English** | [Русский](README.ru.md)

# 🔐 Secure File Encryptor (CLI)

**A command-line utility for authenticated file encryption and digital signing using the Encrypt-then-Sign scheme**

[![Python](https://shields.io)](https://python.org)
[![Cipher](https://shields.io)](#cryptographic-stack)
[![Signature](https://shields.io)](#cryptographic-stack)
[![KDF](https://shields.io)](#cryptographic-stack)
[![Security Tests](https://github.com)](https://github.com)

</div>

---

## 🛡️ Cryptographic Stack

| Component | Algorithm / Standard | Role in the System |
| :--- | :--- | :--- |
| **Symmetric Encryption** | `AES-256-GCM` (AEAD) | Data confidentiality and ciphertext authentication |
| **Key Derivation (KDF)** | `Argon2id` | Protection against GPU/ASIC password cracking (memory-hard) |
| **Digital Signature** | `Ed25519` | Authenticity and container integrity verification prior to decryption |
| **Metadata Protection** | `AAD` (Canonical JSON) | Cryptographic binding of container headers to the GCM tag |

---

## ⚙️ Security Architecture (Encrypt-then-Sign)

```mermaid
flowchart LR
    A[📄 Source File] --> B[🔑 Argon2id KDF<br/>Password + Salt]
    B --> C[🔒 AES-256-GCM<br/>Encryption + AAD]
    C --> D[✍️ Ed25519 Signature<br/>Container Signing]
    D --> E[📦 Protected JSON]

    style A fill:#1e293b,stroke:#38bdf8,color:#fff
    style B fill:#1e293b,stroke:#a855f7,color:#fff
    style C fill:#1e293b,stroke:#10b981,color:#fff
    style D fill:#1e293b,stroke:#f59e0b,color:#fff
    style E fill:#0f172a,stroke:#64748b,color:#fff
```

### Core Security Principles:
1. **Fail-Fast Signature Verification:** During decryption, the utility **first** verifies the `Ed25519` digital signature. If the container has been tampered with, execution aborts before running the resource-intensive `Argon2id` function (DoS protection).
2. **Header Authentication (AAD):** The version, KDF parameters, `salt`, and `nonce` are serialized into canonical JSON and passed to `AESGCM` as Additional Authenticated Data (AAD). Any header tampering makes decryption impossible.
3. **Private Key Protection:** The `Ed25519` private key is stored in `PKCS#8` format, password-encrypted (`BestAvailableEncryption`), and restricted with strict permissions (`0o600` on POSIX systems).

---

## 🎯 Threat Model

### ✅ Mitigated Threats:
* **Ciphertext and Metadata Tampering (Bit-flipping):** Prevented by `Ed25519` signature verification and the `AES-GCM` authentication tag (including AAD).
* **Offline Password Cracking (Brute-Force):** Slowed down by `Argon2id` (64 MB RAM per iteration, 3 passes, 4 threads) combined with a random 128-bit `salt`.
* **Nonce Reuse:** A cryptographically strong random 96-bit `nonce` is generated via `os.urandom` for every encryption operation.
* **DoS via KDF Parameters:** Strict validation of `Argon2id` header parameters prevents an attacker from forcing the application to allocate gigabytes of memory during decryption.

### ⚠️ Limitations and Out-of-Scope Vectors:
* **Host Compromise (Malware / Keyloggers):** Does not protect against password interception on an already compromised operating system.
* **Memory Dump Analysis (Core Dump):** Because Python `str` and `bytes` objects are immutable, keys may remain in RAM until garbage collection *(planned fix using `bytearray` + memory zeroing in v2.0)*.
* **RAM Limitations (OOM):** In `v1.0`, files are loaded entirely into memory and Base64-encoded (+33% size overhead). Files >2 GB require chunked streaming encryption *(planned for v2.0)*.

---

## 🚀 Quick Start

```bash
# 1. Clone the repository and install dependencies
cd Secure-File-Encryptor
pip install -r requirements.txt

# 2. Generate an Ed25519 key pair
python AES.py keygen

# 3. Encrypt a file
python AES.py encrypt secret.txt secret.enc.json

# 4. Decrypt the file and verify the signature
python AES.py decrypt secret.enc.json decrypted.txt
```

---

## 🧪 Security Testing

The project includes a suite of negative tests powered by `pytest` that simulate real-world attack vectors:

```text
tests/test_encryptor.py::test_happy_path_and_empty_file         PASSED [ 16%]
tests/test_encryptor.py::test_bit_flip_in_ciphertext            PASSED [ 33%]
tests/test_encryptor.py::test_aad_header_tampering              PASSED [ 50%]
tests/test_encryptor.py::test_malformed_json_and_missing_fields PASSED [ 66%]
tests/test_encryptor.py::test_downgrade_and_dos_argon_params    PASSED [ 83%]
tests/test_encryptor.py::test_wrong_password_and_wrong_key      PASSED [100%]
```

Run tests locally:
```bash
pytest -v
```

---

## 🗺️ Roadmap and Project Structure

* **[v1.0] (Current Release):** JSON container, `Encrypt-then-Sign` scheme, negative security test suite, and threat model.
* **[v2.0] (Next Milestone):** Streaming binary format (64 KB chunks) for files of any size, chunk counters in AAD to prevent file truncation, and explicit key zeroing in RAM.

## Disclaimer
This project was created for educational and portfolio purposes. The software is provided "as is", without warranty of any kind. Always keep backups of important files before encrypting them.

