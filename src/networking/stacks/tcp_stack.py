from networking.nodes.client_node import client_node
from networking.nodes.node import node
from networking.packet_management.packet_errors import packet_ip_format_unknown_error
from networking.packet_management.packet_flags import packet_flags
from cryptography_engines.cipher import cipher
from cryptography_engines.constant_time import constant_time
from cryptography_engines.hashing import hashing
from cryptography_engines.mac import mac
from cryptography_engines.timestamps import timestamps
from cryptography_engines.warnings import *

from pydivert.packet import Packet, Direction


# TODO -> THIS IS POORLY WRITTEN CODE
# TODO -> BREAK DOWN FLOW METHODS INTO SUB METHODS
# TODO -> MOVE VERIFICATIONS TOGETHER? (OR PUT AT THE END OF SUB METHODS -> CUSTOM DECORATOR?)


class tcp_stack:
    def __init__(self, node_info: node, is_client: bool):
        assert node.initialized

        self._node: node = node_info
        self._is_client: bool = is_client

    def send(self, packet: Packet):
        # flowing up from the web to the node
        print(packet.payload)

        for i in range(self._node.NUMBER_HOPS):
            if not isinstance(self._node, client_node):
                packet = self._internal_flow_up(packet, i)
            else:
                packet = self._internal_flow_down(packet, i)

        print(packet.payload)

    def recv(self, packet: Packet):
        # flowing down from the node to the web
        [self._internal_flow_down(packet, i) if not isinstance(self._node, client_node) else self._internal_flow_up(packet, i) for i in range(self._node.NUMBER_HOPS)]

    def _internal_flow_up(self, packet: Packet, iteration: int):
        # TODO -> ip attachment and flags

        # get the packet payload
        packet_payload: bytes = packet.payload

        # generate a hash of the relay node's public static key and a timestamp
        hashed_their_public_static_key: bytes = b""  # TODO -> already stored from PKI
        hashed_timestamp = timestamps.generate_hashed_timestamp()

        # append these hashes to the packet payload
        ip_address = (self._node.relay_nodes[iteration] if isinstance(self._node, client_node) else self._node.previous_nodes[iteration]).ip_address.to_bytes()
        packet_payload = hashed_timestamp + hashed_their_public_static_key + packet_payload + ip_address
        packet_payload = cipher.encrypt(packet_payload, self._node.shared_secrets[iteration].cipher_key)

        # generate a mac tag and append it to the encrypted packet payload
        mac_tag = mac.generate_tag(packet_payload, self._node.shared_secrets[iteration].mac_key)
        packet_payload += mac_tag

        # update the packet payload and return the packet
        packet.payload = packet_payload
        return packet

        # TODO -> set the next ip address and forward the packet onto the next node (next going backwards)

    def _internal_flow_down(self, packet: Packet, iteration: int):
        # get the packet payload and remove the mac code at the end of it
        packet_payload: bytes = packet.payload
        mac_tag: bytes = packet_payload[-mac.TAG_LENGTH:]
        packet_payload = packet_payload[:-mac.TAG_LENGTH]

        # check that the mac is valid for the encrypted payload
        if not mac.generate_tag_matches(packet_payload, self._node.shared_secrets[iteration].mac_key, mac_tag):
            raise mac_mismatch_warning("Message authentication code doesn't match packet payload (mitigating an altered ciphertext attack)")

        # get the timestamp and public key embedded into the encrypted payload
        packet_payload = cipher.decrypt(packet_payload, self._node.shared_secrets[iteration].cipher_key)
        hashed_timestamp: bytes = packet_payload[:hashing.HASH_LENGTH]
        hashed_my_static_public_key: bytes = packet_payload[hashing.HASH_LENGTH:hashing.HASH_LENGTH * 2]
        packet_payload = packet_payload[hashing.HASH_LENGTH * 2:]

        # check that the timestamp is in tolerance and the public key is this node's static public key
        if not timestamps.is_in_tolerance(hashed_timestamp) or not constant_time.is_equal(self._node.my_static_signing_key_pair.public_key_hashed, hashed_my_static_public_key):
            raise timestamp_out_of_tolerance_warning("Timestamp inside encrypted packet is out of tolerance (mitigating a timing attack)")

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
        if not constant_time.is_equal(next_node_ip_address, self._node.relay_nodes[iteration].ip_address.to_string().encode()):
            raise next_node_ip_address_mismatch_warning("Next node address embedded in packet != known next node address")

        # update the packet payload and return the packet
        packet.payload = packet_payload
        return packet


if __name__ == "__main__":
    from networking.nodes.relay_node import relay_node

    relay_node_1 = relay_node()
    relay_node_2 = relay_node()
    relay_node_3 = relay_node()
    client = client_node(relay_nodes=[relay_node_1, relay_node_2, relay_node_3], auto_initialize=True)

    relay_node_1_stack = tcp_stack(relay_node_1, False)
    relay_node_2_stack = tcp_stack(relay_node_2, False)
    relay_node_3_stack = tcp_stack(relay_node_3, False)
    client_stack = tcp_stack(client, True)

    packet = Packet(b"hello world", 0, Direction.OUTBOUND)
    packet.payload = b"hello world"
    client_stack.send(packet)
