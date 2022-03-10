from typing import Optional

from .node import node
from ..utils.ip import ip


class relay_node(node):
    NUMBER_HOPS: int = 1
    IS_CLIENT: bool = False

    def __init__(self, previous_node_ip_address: ip = ip(), next_node_ip_address: ip = ip()):
        node.__init__(self)
