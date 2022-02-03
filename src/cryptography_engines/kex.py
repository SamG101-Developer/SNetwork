from sibc.sidh import SIDH as algorithm, default_parameters


class kex:
    DLL = algorithm(**default_parameters)

    @staticmethod
    def generate_key_pair(sender: bool) -> tuple[bytes, bytes]:
        return kex.DLL.keygen_a() if sender else kex.DLL.keygen_b()

    @staticmethod
    def compute_shared_secret(my_ephemeral_secret_key: bytes, their_ephemeral_public_key: bytes, sender: bool) -> bytes:
        a = kex.DLL.derive_a(my_ephemeral_secret_key, their_ephemeral_public_key)
        b = kex.DLL.derive_b(my_ephemeral_secret_key, their_ephemeral_public_key)
        return kex.DLL.derive_a(my_ephemeral_secret_key, their_ephemeral_public_key) if sender else kex.DLL.derive_b(my_ephemeral_secret_key, their_ephemeral_public_key)
