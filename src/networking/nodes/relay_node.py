import node


class relay_node(node.node):
    def __init__(self, previous_node_ip, next_node_ip):
        node.node.__init__(self)

        self._shared_secret = None

    @property
    def shared_secret(self):
        return self._shared_secret
