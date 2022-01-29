from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES as algorithm
from cryptography.hazmat.primitives.ciphers.modes import CTR as mode
from cryptography.hazmat.backends import default_backend
import os


class iv_context:
    def __init__(self, nonce=b""):
        self.nonce: bytes = nonce
        self.counter: int = 0

    def iv(self) -> bytes:
        return self.nonce + (self.counter.to_bytes(16 - len(self.nonce), "big"))


class symmetric_cipher:

    @staticmethod
    def generate_key(key_length: int) -> bytes:
        return os.urandom(key_length)

    @staticmethod
    def encrypt(data: bytes, key: bytes, iv: iv_context) -> bytes:
        encryption_engine = Cipher(algorithm(key), mode(iv.iv()), default_backend()).encryptor()
        iv.counter += 1
        return encryption_engine.update(data) + encryption_engine.finalize()

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        decryption_engine = Cipher(algorithm(key), mode(data), default_backend()).decryptor()
        return decryption_engine.update(data) + decryption_engine.finalize()
