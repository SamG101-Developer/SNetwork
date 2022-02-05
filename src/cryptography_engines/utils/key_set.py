from cryptography_engines.kdf import kdf
from cryptography_engines.kem import kem
from cryptography_engines.mac import mac
from cryptography_engines.hashing import hashing
from cryptography_engines.cipher import cipher


class key_set:
    def __init__(self, master_key: bytes, their_ephemeral_public_key: bytes):
        self._master_key: bytes = master_key
        self._cipher_key: bytes = kdf.derive_key(master_key, b"SYMMETRIC_CIPHER", cipher.KEY_LENGTH)
        self._mac_key: bytes = kdf.derive_key(master_key, b"MESSAGE_AUTHENTICATION_CODE", mac.TAG_LENGTH)
        self._hash_key: bytes = hashing.hash(self._mac_key)
        self._encapsulated: bytes = kem.encrypt_kem(their_ephemeral_public_key, master_key)

    @property
    def master_key(self) -> bytes:
        return self._master_key

    @property
    def cipher_key(self) -> bytes:
        return self._cipher_key

    @property
    def mac_key(self) -> bytes:
        return self._mac_key

    @property
    def hash_key(self) -> bytes:
        return self._hash_key

    @property
    def encapsulated(self) -> bytes:
        return self._encapsulated
