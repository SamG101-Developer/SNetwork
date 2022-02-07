from tcp_stack import tcp_stack

from networking.nodes.relay_node import relay_node
from networking.packet_management.packet_errors import packet_ip_format_unknown_error
from networking.packet_management.packet_flags import packet_flags
from cryptography_engines.cipher import cipher
from cryptography_engines.constant_time import constant_time
from cryptography_engines.hashing import hashing
from cryptography_engines.mac import mac
from cryptography_engines.timestamps import timestamps
from cryptography_engines.warnings import *

from pydivert.packet import Packet


class relay_node_stack(tcp_stack):
    def __init__(self, node_info: relay_node):
        tcp_stack.__init__(self, node_info)

    def _flow_up(self, packet: Packet):
        # TODO -> ip attachment and flags
        packet_payload: bytes = packet.payload

        hashed_their_public_static_key: bytes = b""  # TODO -> already stored from PKI
        hashed_timestamp = timestamps.generate_hashed_timestamp()
        packet_payload = hashed_timestamp + hashed_their_public_static_key + packet_payload + self._node.previous_node_ip_address.to_bytes()
        packet_payload = cipher.encrypt(packet_payload, self._node.shared_secret.cipher_key)

        mac_tag = mac.generate_tag(packet_payload, self._node.shared_secret.mac_key)
        packet_payload += mac_tag

        # TODO -> set the next ip address and forward the packet onto the next node (next going backwards)

    def _flow_down(self, packet: Packet):

        # get the packet payload and remove the mac code at the end of it
        packet_payload: bytes = packet.payload
        mac_tag: bytes = packet_payload[-mac.TAG_LENGTH:]
        packet_payload = packet_payload[:-mac.TAG_LENGTH]

        # check that the mac is valid for the encrypted payload
        if not mac.generate_tag_matches(packet_payload, self._node.shared_secret.mac_key, mac_tag):
            raise mac_mismatch_warning("Message authentication code doesn't match packet payload")

        # get the timestamp and public key embedded into the encrypted payload
        packet_payload = cipher.decrypt(packet_payload, self._node.shared_secret.cipher_key)
        hashed_timestamp: bytes = packet_payload[:hashing.HASH_LENGTH]
        hashed_my_static_public_key: bytes = packet_payload[hashing.HASH_LENGTH:hashing.HASH_LENGTH * 2]
        packet_payload = packet_payload[hashing.HASH_LENGTH * 2:]

        # check that the timestamp is in tolerance and the public key is this node's static public key
        if not timestamps.is_in_tolerance(hashed_timestamp) or not constant_time.is_equal(self._node.my_static_signing_key_pair.public_key_hashed, hashed_my_static_public_key):
            raise timestamp_out_of_tolerance_warning("Timestamp inside encrypted packet is out of tolerance")

        # get the 8-bit packet flag stored in the last byte of the payload
        packet_payload_flags: int = packet_payload[-packet_flags.FLAG_LENGTH]
        packet_payload = packet_payload[:-packet_flags.FLAG_LENGTH]
        packet.payload = packet_payload

        # check that the packet flags are valid for ip detection
        if ~(packet_payload_flags & (packet_flags.IPV4 | packet_flags.IPV6)):
            raise packet_ip_format_unknown_error("Packet's contained next node IP must in be IPv4 or IPv6 format")

        # get the next ip address in the circuit based on whether IPv4 ir IPv6 is being used
        next_node_ip_address: bytes = b""
        if packet_payload_flags & packet_flags.IPV6:
            next_node_ip_address = packet_payload[-16:]
            next_node_ip_address = b":".join([next_node_ip_address[i : i + 2] for i in range(0, 16, 2)])
        elif packet_payload_flags & packet_flags.IPV4:
            next_node_ip_address = packet.payload[-4:]
            next_node_ip_address = b".".join([next_node_ip_address[i : i + 1] for i in range(0, 4, 1)])

        # check that the next node's ip address is correct
        if not constant_time.is_equal(next_node_ip_address, self._node.next_node_ip_address.to_string().encode()):
            raise next_node_ip_address_mismatch_warning("Next node address embedded in packet != known next node address")
