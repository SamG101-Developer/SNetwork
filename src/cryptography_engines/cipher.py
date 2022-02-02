from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES as algorithm
from cryptography.hazmat.primitives.ciphers.modes import CTR as mode
import os

from .kdf import kdf
from .mac import mac
from .hashing import hashing


class cipher:
    KEY_LENGTH: int = 32

    @staticmethod
    def generate_key(key_length: int = 32) -> bytes:
        return os.urandom(key_length)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        iv = os.urandom(8) + int(0).to_bytes(length=8, byteorder="little")
        encryption_engine = Cipher(algorithm(key), mode(iv)).encryptor()
        return iv + encryption_engine.update(data) + encryption_engine.finalize()

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        decryption_engine = Cipher(algorithm(key), mode(data[:16])).decryptor()
        return decryption_engine.update(data[16:]) + decryption_engine.finalize()


class key_set:
    def __init__(self, master_key: bytes):
        self.master_key: bytes = master_key
        self.cipher_key: bytes = kdf.derive_key(self.master_key, b"SYMMETRIC_CIPHER", cipher.KEY_LENGTH)
        self.mac_key: bytes = kdf.derive_key(self.master_key, b"MESSAGE_AUTHENTICATION_CODE", mac.TAG_LENGTH)
        self.hash_key: bytes = hashing.hash(self.mac_key)
