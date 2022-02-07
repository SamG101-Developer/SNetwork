from node import node


class client_node(node):
    NUMBER_HOPS: int = 3

    def __init__(self):
        node.__init__(self)

    def initialize(self) -> None:
        self._shared_secrets = [
            # kex.compute_shared_secret(my_ephemeral_secret_key, their_ephemeral_public_key) for my_ephemeral_secret_key, their_ephemeral_public_key in zip(self._)
        ]

    def _compare_signed_hash(self) -> bool:
        pass
