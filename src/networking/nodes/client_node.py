from node import node
from relay_node import relay_node

from cryptography_engines.utils.key_set import key_set
from cryptography_engines.kex import kex, key_pair


class client_node(node):
    NUMBER_HOPS: int = 3

    def __init__(self):
        node.__init__(self)

        self._relay_nodes: list[relay_node] = []
        self._shared_secrets: list[key_set] = []
        self._ephemeral_kex_key_pairs: list[key_pair] = []
        self._their_static_signing_keys: list[key_pair] = []

    def initialize(self) -> None:
        self._shared_secrets = [
            # kex.compute_shared_secret(my_ephemeral_secret_key, their_ephemeral_public_key) for my_ephemeral_secret_key, their_ephemeral_public_key in zip(self._)
        ]

    def _compare_signed_hash(self) -> bool:
        pass

    @property
    def relay_nodes(self) -> list[relay_node]:
        return self._relay_nodes

    @property
    def shared_secrets(self) -> list[key_set]:
        return self._shared_secrets

    @property
    def their_static_signing_keys(self) -> list[key_pair]:
        return self._their_static_signing_keys
