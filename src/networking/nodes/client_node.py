from .node import node


class client_node(node):
    NUMBER_HOPS: int = 3
    IS_CLIENT: bool = True

    def __init__(self, **kwargs):
        node.__init__(self, **kwargs)

    def _compare_signed_hash(self) -> bool:
        pass
