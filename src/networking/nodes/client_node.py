from node import node

from cryptography_engines.utils.key_set import key_set
from cryptography_engines.kex import kex, key_pair


class client_node(node):
    NUMBER_HOPS: int = 3

    def __init__(self):
        node.__init__(self)

        self._shared_secrets: list[key_set] = []
        self._next_nodes: list[node] = []
        self._ephemeral_kex_key_pairs: list[key_pair] = []

    def initialize(self):
        self._shared_secrets = [
            # kex.compute_shared_secret(my_ephemeral_secret_key, their_ephemeral_public_key) for my_ephemeral_secret_key, their_ephemeral_public_key in zip(self._)
        ]

    def _compare_signed_hash(self):
        pass
