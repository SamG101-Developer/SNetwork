from sibc.sidh import SIKE as algorithm, default_parameters


class kem:
    DLL = algorithm(**default_parameters)

    @staticmethod
    def encrypt_kem(their_ephemeral_public_key: bytes, plain_text: bytes) -> bytes:
        return kem.DLL.Encaps(their_ephemeral_public_key, plain_text)[0]

    @staticmethod
    def decrypt_kem(my_ephemeral_secret_key: bytes, my_ephemeral_public_key: bytes, encapsulated: bytes) -> bytes:
        s = kem.DLL.sidh.strategy.random.randint(0, 2 ** kem.DLL.n)
        s = s.to_bytes(length=kem.DLL.n_bytes, byteorder="little")
        return kem.DLL.Decaps((s, my_ephemeral_secret_key, my_ephemeral_public_key), encapsulated)
