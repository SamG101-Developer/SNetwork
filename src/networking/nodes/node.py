import abc

from cryptography_engines.signing import signing
from cryptography_engines.utils.key_pair import key_pair


class node(abc.ABC):
    def __init__(self):
        self._my_static_signing_key_pair: key_pair = signing.import_keypair()
        self._initialized: bool = False

    @abc.abstractmethod
    def initialize(self):
        pass

    @property
    def my_static_signing_key_pair(self) -> key_pair:
        return self._my_static_signing_key_pair
