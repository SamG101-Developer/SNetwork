import abc

from ..nodes.node import node

from pydivert.packet import Packet


class tcp_stack(abc.ABC):
    def __init__(self, node_info: node):
        self._node: node = node_info

    @abc.abstractmethod
    def _flow_up(self, packet: Packet):
        pass

    @abc.abstractmethod
    def _flow_down(self, packet: Packet):
        pass
