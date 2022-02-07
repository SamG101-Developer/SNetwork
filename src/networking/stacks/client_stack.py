from cryptography_engines.cipher import cipher
from cryptography_engines.mac import mac
from cryptography_engines.timestamps import timestamps
from cryptography_engines.utils.key_set import key_set
from tcp_stack import tcp_stack
from networking.nodes.client_node import client_node
from networking.nodes.utils.ip import ip

from pydivert.packet import Packet


class client_stack(tcp_stack):
    def __init__(self, node_info: client_node):
        tcp_stack.__init__(self, node_info)

        self._number_hops = 3

    def _flow_up(self, packet: Packet):
        # capture the current packet payload
        packet_payload: bytes = packet.payload

        for i in range(self._number_hops - 1, -1, -1):
            # get the current shared secret key set
            current_key_set: key_set = self._node.shared_secrets[i]

            # append the next node's ip address to the raw packet payload
            packet_payload += self._node.relay_nodes[i].ip_address

            # create a hash of the relay node's public key and the timestamp
            hashed_their_static_public_key = self._node.their_static_signing_keys[i].public_key_hashed
            hashed_timestamp = timestamps.generate_hashed_timestamp()
            packet_payload = hashed_timestamp + hashed_their_static_public_key + packet_payload

            # encrypt the payload under a symmetric key derived from the shared secret
            packet_payload = cipher.encrypt(packet_payload, current_key_set.cipher_key)

            # generate the mac tag from the encrypted payload
            mac_tag = mac.generate_tag(packet_payload, current_key_set.mac_key)
            packet_payload += mac_tag

        # set the packet's payload to the encrypted payload
        packet.payload = packet_payload

    def _flow_down(self, packet: Packet):
        # capture the current packet payload
        packet_payload: bytes = packet.payload

        for i in range(self._number_hops):
            # get the current shared secret key set
            current_key_set: key_set = self._node.shared_secrets[i]
