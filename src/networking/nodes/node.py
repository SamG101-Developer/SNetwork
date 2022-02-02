from relay import relay_node_info
from cryptography_engines.kex import kex
from cryptography_engines.kem import kem
from cryptography_engines.cipher import key_set
from cryptography_engines.constant_time import constant_time


class node:
    HOP_COUNT = 0
    IS_CLIENT = False

    def __init__(self, relay_nodes: list[relay_node_info]):
        self._my_ephemeral_kex_keys: list[tuple[bytes, bytes]]
        self._other_nodes_info: list[relay_node_info]
        self._shared_secrets: list[key_set]
        self._encapsulated_shared_secrets: list[bytes]

        self._my_ephemeral_kex_keys = [kex.generate_key_pair(self.IS_CLIENT) for _ in range(self.HOP_COUNT)]
        self._other_nodes_info = relay_nodes
        self._shared_secrets = []
        self._encapsulated_shared_secrets = []

        self._compute_new_shared_secrets()
        self._compute_kem_shared_secrets()

    def _compute_new_shared_secrets(self) -> None:
        for i in range(self.HOP_COUNT):
            my_ephemeral_secret_key: bytes = self._my_ephemeral_kex_keys[i][0]
            their_ephemeral_public_key: bytes = self._other_nodes_info[i].ephemeral_public_key
            shared_secret: bytes = kex.compute_shared_secret(my_ephemeral_secret_key, their_ephemeral_public_key, self.IS_CLIENT)
            self._shared_secrets.append(key_set(shared_secret))

    def _compute_kem_shared_secrets(self) -> None:
        for i in range(self.HOP_COUNT):
            their_ephemeral_public_key: bytes = self._other_nodes_info[i].ephemeral_public_key
            shared_secret: bytes = self._shared_secrets[i].master_key
            encapsulated_symmetric_master_key = kem.encrypt_kem(their_ephemeral_public_key, shared_secret)
            self._encapsulated_shared_secrets.append(encapsulated_symmetric_master_key)

    def _compare_signed_hashed_shared_secrets(self, hashed_signed_shared_secrets) -> bool:
        known_hashes = map(lambda keys: keys.hashed_key, self._shared_secrets)
        check_hashes = map(lambda keys: keys.hashed_key, hashed_signed_shared_secrets)
        return all([constant_time.is_equal(known_hash, check_hash) for known_hash, check_hash in zip(known_hashes, check_hashes)])


class client(node):
    HOP_COUNT = 3
    IS_CLIENT = True


class relay_node(node):
    HOP_COUNT = 1
    IS_CLIENT = False


if __name__ == "__main__":
    from pprint import pprint

    # Client perspective:
    client_info = relay_node_info()
    client_info.ephemeral_public_key = kex.generate_key_pair(True)[0]

    relay_node_1 = relay_node([client_info])
    relay_node_1_info = relay_node_info()
    relay_node_1_info.ip = "xxx.xxx.xxx.xxx"
    relay_node_1_info.ephemeral_public_key = kex.generate_key_pair(False)[0]  # RECV

    relay_node_2 = relay_node([client_info])
    relay_node_2_info = relay_node_info()
    relay_node_2_info.ip = "yyy.yyy.yyy.yyy"
    relay_node_2_info.ephemeral_public_key = kex.generate_key_pair(False)[0]  # RECV

    relay_node_3 = relay_node([client_info])
    relay_node_3_info = relay_node_info()
    relay_node_3_info.ip = "zzz.zzz.zzz.zzz"
    relay_node_3_info.ephemeral_public_key = kex.generate_key_pair(False)[0]  # RECV

    client = client([relay_node_1_info, relay_node_2_info, relay_node_3_info])

    print("\nClient:")
    for key in client._my_ephemeral_kex_keys: print(key)
    print()
    for ss in client._shared_secrets: print(ss)

    print("\nRN_1")
    for key in relay_node_1._my_ephemeral_kex_keys: print(key)

    print("\nRN_2")
    for key in relay_node_2._my_ephemeral_kex_keys: print(key)

    print("\nRN_3")
    for key in relay_node_3._my_ephemeral_kex_keys: print(key)
