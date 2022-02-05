from tcp_stack import tcp_stack
from networking.nodes.node import client


class client_stack(tcp_stack):
    def __init__(self, client_node: client):
        tcp_stack.__init__(self)

        self._client: client = client_node

