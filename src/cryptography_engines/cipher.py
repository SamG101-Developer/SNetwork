from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES as algorithm
from cryptography.hazmat.primitives.ciphers.modes import CTR as mode
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
import os


class cipher:
    """
    symmetric cipher works like: increase counter per packet encrypted. change nonce per tcp stream (nonce is the hash
    of the stream id). form the iv by concatenating the counter to the nonce. change key every 20 seconds with key
    wrapping.
    """

    # length of the symmetric encryption key
    KEY_LENGTH: int = 32

    @staticmethod
    def generate_key(key_length: int = 32) -> bytes:
        # generate a random symmetric encryption key from a cryptographically secure pseudo random number generator
        return os.urandom(key_length)

    @staticmethod
    def wrap_new_key(current_key: bytes, new_key: bytes = os.urandom(KEY_LENGTH)) -> bytes:
        # wrap a new aes key with a current aes key
        return aes_key_wrap(current_key, new_key)

    @staticmethod
    def unwrap_new_key(current_key: bytes, new_key: bytes = os.urandom(KEY_LENGTH)) -> bytes:
        # unwrap a new aes key with a current aes key
        return aes_key_unwrap(current_key, new_key)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        # create a random iv, and encrypt the data with the key and iv
        iv: bytes = os.urandom(8) + int(0).to_bytes(length=8, byteorder="little")  # TODO
        encryption_engine = Cipher(algorithm(key), mode(iv)).encryptor()
        return iv + encryption_engine.update(data) + encryption_engine.finalize()

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        # get the iv, and decrypt the data with the key and iv
        decryption_engine = Cipher(algorithm(key), mode(data[:16])).decryptor()
        return decryption_engine.update(data[16:]) + decryption_engine.finalize()
