import abc

from networking.nodes.client_node import client_node
from networking.nodes.relay_node import relay_node

from pydivert.packet import Packet


class tcp_stack(abc.ABC):
    def __init__(self, node_info: client_node | relay_node):
        self._node: client_node | relay_node = node_info

    @abc.abstractmethod
    def _flow_up(self, packet: Packet):
        pass

    @abc.abstractmethod
    def _flow_down(self, packet: Packet):
        pass
