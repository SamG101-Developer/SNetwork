from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES as algorithm
from cryptography.hazmat.primitives.ciphers.modes import CTR as mode
import os


class cipher:

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
