from __future__ import annotations

import abc

from networking.utils.ip import ip
from cryptography_engines.kex import kex
from cryptography_engines.signing import signing
from cryptography_engines.utils.key_pair import key_pair
from cryptography_engines.utils.key_set import key_set


class node(abc.ABC):
    NUMBER_HOPS: int = 0
    IS_CLIENT: bool = False

    def __init__(self, **kwargs):
        self._ip_address: ip = ip("")  # TODO -> securely determine own external ip address
        self._relay_nodes: list[node] = kwargs.get("relay_nodes", [])
        self._initialized: bool = kwargs.get("initialized", False)

        self._my_static_signing_key_pair: key_pair = key_pair()  # signing.import_keypair("") TODO
        self._their_static_signing_key_pairs: list[key_pair] = []
        self._my_ephemeral_kex_key_pairs: list[key_pair] = [kex.generate_key_pair(self.IS_CLIENT) for i in range(self.NUMBER_HOPS)]
        self._their_ephemeral_kex_key_pairs: list[key_pair] = [relay_node.my_ephemeral_kex_key_pairs[0] for relay_node in self._relay_nodes]
        self._shared_secrets: list[key_set] = []

        for relay_node in self._relay_nodes:
            relay_node.initialize()

    def initialize(self):
        print(id(self), self._my_ephemeral_kex_key_pairs, self._their_ephemeral_kex_key_pairs)
        self._shared_secrets = [
            kex.compute_shared_secret(
                my_ephemeral_kex_key_pair.secret_key,
                their_ephemeral_kex_key_pair.public_key,
                self.IS_CLIENT)

            for my_ephemeral_kex_key_pair, their_ephemeral_kex_key_pair in zip(self._my_ephemeral_kex_key_pairs, self._their_ephemeral_kex_key_pairs)
        ]

    @property
    def ip_address(self) -> ip:
        return self._ip_address

    @property
    def relay_nodes(self) -> list[node]:
        return self._relay_nodes

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def my_static_signing_key_pair(self) -> key_pair:
        return self._my_static_signing_key_pair

    @property
    def my_ephemeral_kex_key_pairs(self) -> list[key_pair]:
        return self._my_ephemeral_kex_key_pairs

    @property
    def shared_secrets(self) -> list[key_set]:
        return self._shared_secrets
