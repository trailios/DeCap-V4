import base64
import hashlib
import json, time
import os
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class EncryptionData:
    def __init__(self, ct: str, iv: str, s: str) -> None:
        self.ct = ct
        self.iv = iv
        self.s = s


def aes_encrypt(content: str, password: str) -> str:
    salt: bytes = os.urandom(8)
    key, iv = default_evp_kdf(password.encode(), salt)

    padder = padding.PKCS7(128).padder()
    padded_data: bytes = padder.update(content.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text: bytes = encryptor.update(padded_data) + encryptor.finalize()

    ciphertext_encoded: str = base64.b64encode(cipher_text).decode("utf-8")

    iv_hex: str = iv.hex()
    salt_hex: str = salt.hex()

    enc_data = EncryptionData(ciphertext_encoded, iv_hex, salt_hex)

    return json.dumps(enc_data.__dict__)


def aes_decrypt(encrypted_content: str, password: str) -> str:
    enc_data: dict = json.loads(encrypted_content)
    ciphertext: bytes = base64.b64decode(enc_data["ct"])
    iv: bytes = bytes.fromhex(enc_data["iv"])
    salt: bytes = bytes.fromhex(enc_data["s"])

    key, _ = default_evp_kdf(password.encode(), salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded: bytes = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data: bytes = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted_data.decode("utf-8")


def evp_kdf(
    password: bytes,
    salt: bytes,
    key_size: int = 32,
    iv_size: int = 16,
    iterations: int = 1,
    hash_algorithm: str = "md5",
) -> Tuple[bytes, bytes]:
    if hash_algorithm.lower() != "md5":
        raise ValueError("Unsupported hash algorithm")

    derived_key_bytes: bytes = b""
    block: bytes = b""

    while len(derived_key_bytes) < (key_size + iv_size):
        hasher = hashlib.md5()
        hasher.update(block + password + salt)
        block = hasher.digest()

        for _ in range(1, iterations):
            hasher = hashlib.md5()
            hasher.update(block)
            block = hasher.digest()

        derived_key_bytes += block

    return (
        derived_key_bytes[:key_size],
        derived_key_bytes[key_size : key_size + iv_size],
    )


def default_evp_kdf(password: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    return evp_kdf(password, salt)


if __name__ == "__main__":
    timestamp = int(time.time())
    bda: str = (
        '{"ct":"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","s":"27f1469b6ea70d75","iv":"12e59c199cc2acc1116cd0fa7e3d1e52"}'
        )
    timeframe = int(timestamp - (timestamp % 21600))
    encryption_key = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"
        + str(timeframe)
    )
    enckey = "711180924aa280dd8.9631261505"
    bdadecrypted = aes_decrypt(bda, encryption_key)
    print(bdadecrypted)
