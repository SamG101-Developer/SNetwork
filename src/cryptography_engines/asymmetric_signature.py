from pqcrypto.sign import dilithium4 as algorithm


class asymmetric_signature:

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        return algorithm.generate_keypair()

    @staticmethod
    def sign_message(my_private_key: bytes, hashed_message: bytes) -> bytes:
        return algorithm.sign(my_private_key, hashed_message)

    @staticmethod
    def verify_signature(their_public_key: bytes, hashed_message: bytes, signature: bytes) -> bool:
        return algorithm.verify(their_public_key, hashed_message, signature)

    @staticmethod
    def import_keypair(file_path: str) -> tuple[bytes, ...]:
        return *open(file_path, "rb").read().split(b"-"),

    @staticmethod
    def export_keypair(file_path: str, my_public_key: bytes, my_private_key: bytes) -> None:
        open(file_path, "wb").write(b"-".join((my_public_key, my_private_key)))
