import time

from pqcrypto.sign import rainbowIa_cyclic_compressed as algorithm


# TODO : timestamp signatures
# TODO : verify signature then timestamp is unknown
class signing:
    PUBLIC_KEY_LENGTH = algorithm.PUBLIC_KEY_SIZE
    SECRET_KEY_LENGTH = algorithm.SECRET_KEY_SIZE
    SIGNATURE_LENGTH  = algorithm.SIGNATURE_SIZE

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        return algorithm.generate_keypair()

    @staticmethod
    def sign_message(my_secret_key: bytes, hashed_message: bytes) -> bytes:
        return algorithm.sign(my_secret_key, hashed_message)

    @staticmethod
    def verify_signature(their_public_key: bytes, hashed_message: bytes, signature: bytes) -> bool:
        return algorithm.verify(their_public_key, hashed_message, signature)

    @staticmethod
    def import_keypair(file_path: str) -> tuple[bytes, ...]:
        return *open(file_path, "rb").read().split(b"-"),

    @staticmethod
    def export_keypair(file_path: str, my_public_key: bytes, my_secret_key: bytes) -> None:
        open(file_path, "wb").write(b"-".join((my_secret_key, my_public_key)))

    @staticmethod
    def timestamp():
        return str(time.time()).encode() + b"#"
