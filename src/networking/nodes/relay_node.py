from typing import Optional

from cryptography_engines.utils.key_set import key_set
from node import node
from utils.ip import ip


class relay_node(node):
    def __init__(self, previous_node_ip_address: ip, next_node_ip_address: ip):
        node.__init__(self)

        self._shared_secret: Optional[key_set] = None
        self._previous_node_ip_address: ip = previous_node_ip_address
        self._next_node_ip_address: ip = next_node_ip_address

    @property
    def shared_secret(self):
        return self._shared_secret
    
    @property
    def previous_node_ip_address(self) -> ip:
        return self._previous_node_ip_address
    
    @property
    def next_node_ip_address(self) -> ip:
        return self._next_node_ip_address
