from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES as algorithm
from cryptography.hazmat.primitives.ciphers.modes import CTR as mode
from cryptography.hazmat.backends import default_backend
import os


class iv_context:
    def __init__(self):
        self.counter: int = 0
        self.nonce: bytes = b""

    def iv(self) -> bytes:
        return self.nonce + (self.counter.to_bytes(16 - len(self.nonce), "big"))


class symmetric_cipher:

    @staticmethod
    def generate_key(key_length: int):
        return os.urandom(key_length)

    @staticmethod
    def encrypt(data: bytes, key: bytes, iv: iv_context):
        encryption_engine = Cipher(algorithm(key), mode(iv.iv())).encryptor()
        return encryption_engine.update(data) + encryption_engine.finalize()

    @staticmethod
    def decrypt(data: bytes, key: bytes):
        decryption_engine = Cipher(algorithm(key), mode(data[:16])).decryptor()
        return decryption_engine.update(data) + decryption_engine.finalize()
