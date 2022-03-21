from .utils.key_pair import key_pair

from sibc.sidh import SIDH as algorithm, default_parameters


class kex:
    """
    collection of kex methods ie generating ephemeral keys (in a pair), and calculating a shared secret from Alice's
    ephemeral private key and Bob's ephemeral public key
    """

    # dll backend for SIDH key generation
    DLL = algorithm(**default_parameters)

    @staticmethod
    def generate_key_pair(sender: bool) -> key_pair:
        # generate a key pair (tuple format) and map it into a key pair object
        key_pair_tuple: tuple[bytes, ...] = kex.DLL.keygen_a() if sender else kex.DLL.keygen_b()
        return key_pair(*key_pair_tuple)

    @staticmethod
    def compute_shared_secret(my_ephemeral_secret_key: bytes, their_ephemeral_public_key: bytes, sender: bool) -> bytes:
        # derive a shared secret from ephemeral keys
        return kex.DLL.derive_a(my_ephemeral_secret_key, their_ephemeral_public_key) if sender else kex.DLL.derive_b(my_ephemeral_secret_key, their_ephemeral_public_key)
