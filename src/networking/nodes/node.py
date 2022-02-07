import abc

from cryptography_engines.signing import signing
from cryptography_engines.utils.key_pair import key_pair
from utils.ip import ip


class node(abc.ABC):
    def __init__(self):
        self._my_static_signing_key_pair: key_pair = signing.import_keypair()
        self._initialized: bool = False
        self._ip_address: ip = ip("")  # TODO -> securely determine own external ip address

    @property
    def ip_address(self) -> bytes:
        return self._ip_address.to_bytes()

    @abc.abstractmethod
    def initialize(self):
        pass

    @property
    def my_static_signing_key_pair(self) -> key_pair:
        return self._my_static_signing_key_pair
