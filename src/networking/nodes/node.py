from __future__ import annotations

import abc

from cryptography_engines.signing import signing
from cryptography_engines.utils.key_pair import key_pair
from cryptography_engines.utils.key_set import key_set
from utils.ip import ip


class node(abc.ABC):
    NUMBER_HOPS: int = 0

    def __init__(self):
        self._my_static_signing_key_pair: key_pair = signing.import_keypair()
        self._their_static_signing_key_pairs: list[key_pair] = []
        self._shared_secrets: list[key_set] = []
        self._ephemeral_kex_key_pairs: list[key_pair] = []

        self._ip_address: ip = ip("")  # TODO -> securely determine own external ip address
        self._relay_nodes: list[node] = []
        self._initialized: bool = False

    @abc.abstractmethod
    def initialize(self):
        pass

    @property
    def my_static_signing_key_pair(self) -> key_pair:
        return self._my_static_signing_key_pair

    @property
    def shared_secrets(self) -> list[key_set]:
        return self._shared_secrets

    @property
    def ephemeral_kex_key_pairs(self) -> list[key_pair]:
        return self._ephemeral_kex_key_pairs

    @property
    def ip_address(self) -> ip:
        return self._ip_address

    @property
    def relay_nodes(self) -> list[node]:
        return self._relay_nodes
