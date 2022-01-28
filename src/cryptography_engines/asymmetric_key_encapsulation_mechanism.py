from pqcrypto.kem import kyber1024 as algorithm


class asymmetric_key_encapsulation_mechanism:

    @staticmethod
    def generate_keypair():
        return algorithm.generate_keypair()

    @staticmethod
    def decrypt_kem(my_private_key: bytes, kem: bytes) -> bytes:
        return algorithm.decrypt(my_private_key, kem)

    @staticmethod
    def encrypt_kem(their_public_key: bytes) -> tuple[bytes, bytes]:
        return algorithm.encrypt(their_public_key)
