from node import node
from utils.ip import ip


class relay_node(node):
    def __init__(self, previous_node_ip_address: ip, next_node_ip_address: ip):
        node.__init__(self)

        self._previous_nodes: list[node] = []
    
    @property
    def previous_nodes(self) -> list[node]:
        return self._previous_nodes
