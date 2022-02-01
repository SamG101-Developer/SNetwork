import sibc.sidh


class asymmetric_kem:
    DLL = sibc.sidh.SIKE(**sibc.sidh.default_parameters)

    @staticmethod
    def encrypt_kem(their_ephemeral_public_key: bytes) -> tuple[bytes, bytes]:
        return asymmetric_kem.DLL.Encaps(their_ephemeral_public_key)

    @staticmethod
    def decrypt_kem(my_ephemeral_private_key: bytes, my_ephemeral_public_key: bytes, kem: bytes) -> bytes:
        s = asymmetric_kem.DLL.sidh.strategy.random.randint(0, 2 ** asymmetric_kem.DLL.n)
        s = s.to_bytes(length=asymmetric_kem.DLL.n_bytes, byteorder="little")
        return asymmetric_kem.DLL.Decaps((s, my_ephemeral_private_key, my_ephemeral_public_key), kem)
