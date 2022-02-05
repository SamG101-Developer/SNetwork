from tcp_stack import tcp_stack

from networking.nodes.node import relay_node
from networking.packet_management.packet_flags import packet_flags
from cryptography_engines.cipher import cipher
from cryptography_engines.constant_time import constant_time
from cryptography_engines.hashing import hashing
from cryptography_engines.mac import mac
from cryptography_engines.timestamps import timestamps
from cryptography_engines.warnings import timestamp_out_of_tolerance_warning, mac_mismatch_warning

from pydivert.packet import Packet


class relay_node_stack(tcp_stack):
    def __init__(self, node_info: relay_node):
        tcp_stack.__init__(self, node_info)

    def _flow_down(self, packet: Packet):
        # get the packet payload and remove the mac code at the end of it
        packet_payload: bytes = packet.payload
        mac_tag: bytes = packet_payload[-mac.TAG_LENGTH:]
        packet_payload = packet_payload[:-mac.TAG_LENGTH]

        # check that the mac is valid for the encrypted payload
        if not mac.generate_tag_matches(packet_payload, self._node.shared_secrets[0].mac_key, mac_tag):
            raise mac_mismatch_warning("Message authentication code doesn't match packet payload")

        # get the timestamp and public key embedded into the encrypted payload
        packet_payload = cipher.decrypt(packet_payload, self._node.shared_secrets[0].cipher_key)
        time_stamp = packet_payload[:hashing.HASH_LENGTH]
        my_static_public_key = packet_payload[hashing.HASH_LENGTH:hashing.HASH_LENGTH * 2]
        packet_payload = packet_payload[hashing.HASH_LENGTH * 2:]

        # check that the timestamp is in tolerance and the public key is this node's static public key
        if not timestamps.is_in_tolerance(time_stamp) or not constant_time.is_equal(self._node.my_static_sign_key_pairs[1], my_static_public_key):
            raise timestamp_out_of_tolerance_warning("Timestamp inside encrypted packet is out of tolerance")

        # get the 8-bit packet flag stored in the last byte of the payload
        packet_payload_flags = packet_payload[-1]
        packet_payload = packet_payload[:-1]

        # get the next ip address in the circuit based on whether IPv4 ir IPv6 is being used
        if packet_payload_flags & packet_flags.IPV6:
            next_node_ip_address = packet_payload[-16:]
            next_node_ip_address = ":".join([next_node_ip_address[i : i + 2] for i in range(0, 16, 2)])
        else:
            next_node_ip_address = packet.payload[-4:]
            next_node_ip_address = ".".join([next_node_ip_address[i] for i in range(0, 4, 1)])

        # TODO -> This layer completed
