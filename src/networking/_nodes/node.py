from __future__ import annotations

from cryptography_engines.kex import kex
from cryptography_engines.cipher import key_set
from cryptography_engines.constant_time import constant_time
from cryptography_engines.signing import signing


class node:
    HOP_COUNT = 0
    IS_CLIENT = False

    def __init__(self, next_nodes: list[node] = [], auto_initialize: bool = False):
        self._my_static_sign_key_pairs = signing.import_keypair("static_rainbow_i.keys")
        self._my_ephemeral_kex_key_pairs = [kex.generate_key_pair(self.IS_CLIENT) for _ in range(self.HOP_COUNT)]
        self._shared_secrets = []
        self._encapsulated_shared_secrets = []
        self._next_nodes = next_nodes

        self._initialized = False
        if auto_initialize:
            self.initialize()

    def initialize(self):
        self._initialized = True
        self._compute_new_shared_secrets()

    def _compute_new_shared_secrets(self) -> None:
        if not self._initialized: raise RuntimeError("Node must be initialized - call node.initialize()")

        for i in range(self.HOP_COUNT):
            my_ephemeral_secret_key: bytes = self._my_ephemeral_kex_key_pairs[i][0]
            their_ephemeral_public_key: bytes = self._next_nodes[i]._my_ephemeral_kex_key_pairs[0][1]
            shared_secret: bytes = kex.compute_shared_secret(my_ephemeral_secret_key, their_ephemeral_public_key, self.IS_CLIENT)
            self._shared_secrets.append(key_set(shared_secret, their_ephemeral_public_key))

    def _compare_signed_hashed_shared_secrets(self, hashed_signed_shared_secrets) -> bool:
        known_hashes = map(lambda keys: keys.hashed_key, self._shared_secrets)
        check_hashes = map(lambda keys: keys.hashed_key, hashed_signed_shared_secrets)
        return all([constant_time.is_equal(known_hash, check_hash) for known_hash, check_hash in
                    zip(known_hashes, check_hashes)])

    def single_key(self, index: int):
        copy = node()
        copy._my_ephemeral_kex_key_pairs = self._my_ephemeral_kex_key_pairs
        copy._next_nodes = self._next_nodes
        copy._shared_secrets = self._shared_secrets
        copy._encapsulated_shared_secrets = self._encapsulated_shared_secrets

        copy._my_ephemeral_kex_key_pairs = [copy._my_ephemeral_kex_key_pairs[index]]
        return copy

    @property
    def shared_secrets(self) -> list[key_set]:
        return self._shared_secrets

    @property
    def my_static_sign_key_pairs(self) -> tuple[bytes, ...]:
        return self._my_static_sign_key_pairs


class client_node(node):
    HOP_COUNT = 3
    IS_CLIENT = True


class relay_node(node):
    HOP_COUNT = 1
    IS_CLIENT = False


if __name__ == "__main__":
    # Client perspective:
    relay_node_1 = relay_node()
    relay_node_2 = relay_node()
    relay_node_3 = relay_node()

    client = client_node([relay_node_1, relay_node_2, relay_node_3], auto_initialize=True)

    relay_node_1._next_nodes = [client.single_key(0)]
    relay_node_1.initialize()
    relay_node_2._next_nodes = [client.single_key(1)]
    relay_node_2.initialize()
    relay_node_3._next_nodes = [client.single_key(2)]
    relay_node_3.initialize()

    print("\nClient:")
    # for key in client._my_ephemeral_kex_keys: print(key)
    # print()
    for ss in client._shared_secrets: print(ss.master_key)
    # print()
    # for o in client._other_nodes: print(o._my_ephemeral_kex_keys)

    print("\nRN_1")
    # for key in relay_node_1._my_ephemeral_kex_keys: print(key)
    for ss in relay_node_1._shared_secrets: print(ss.master_key)
    # for o in relay_node_1._other_nodes: print(o._my_ephemeral_kex_keys)

    print("\nRN_2")
    # for key in relay_node_2._my_ephemeral_kex_keys: print(key)
    for ss in relay_node_2._shared_secrets: print(ss.master_key)
    # for o in relay_node_2._other_nodes: print(o._my_ephemeral_kex_keys)

    print("\nRN_3")
    # for key in relay_node_3._my_ephemeral_kex_keys: print(key)
    for ss in relay_node_3._shared_secrets: print(ss.master_key)
    # for o in relay_node_3._other_nodes: print(o._my_ephemeral_kex_keys)
