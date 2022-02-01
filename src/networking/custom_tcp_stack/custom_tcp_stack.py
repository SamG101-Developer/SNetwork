from enum import Enum
from itertools import islice
from math import ceil
from os import urandom
from threading import Thread as thread, current_thread
from typing import Optional
from queue import Queue as queue

from .layer6_presentation import layer6_presentation
from ..packet_management.packet_injector import packet_injector
from ..packet_management.packet_interceptor import packet_interceptor
from ...cryptography_engines.symmetric_cipher import symmetric_cipher, iv_context
from ...cryptography_engines.message_authentication_codes import message_authentication_codes
from ...cryptography_engines.asymmetric_key_encapsulation_mechanism import asymmetric_key_encapsulation_mechanism
from ...cryptography_engines.key_derivation_function import key_derivation_function
from ...cryptography_engines.hash_algorithm import hash_algorithm

from pydivert.packet import Packet


class stack_direction(Enum):
    down = 0
    up = 1


class custom_tcp_stack:
    def __init__(self, master_key: bytes, is_client: bool = False):
        self._packet_injector = packet_injector(self)
        self._packet_interceptor = packet_interceptor(self)
        self._is_client = is_client

        if self._is_client:
            self._relay_node_layers = 3

            self._packet_symmetric_encryption_ivs = []
            self._packet_symmetric_encryption_keys = []
            self._packet_kmac_keys = []

        else:
            self._ephemeral_public_asymmetric_kem_key, self._ephemeral_private_asymmetric_kem_key = asymmetric_key_encapsulation_mechanism.generate_keypair()

        self._connection_symmetric_encryption_iv     = iv_context(urandom(16))  # one time use so can be random
        self._connection_symmetric_encryption_key    = key_derivation_function.generate_tag(master_key, hash_algorithm.hash(b"SYMMETRIC"), 32)
        self._connection_kmac_key                    = key_derivation_function.generate_tag(master_key, hash_algorithm.hash(b"MAC"), 16)
        self._connection_asymmetric_signature_key    = b""
        self._connection_asymmetric_verification_key = b""

        self._initialize_cryptographic_keys()


        self._flow_down_queue = queue()
        self._flow_up_queue = queue()

        self._flow_down_thread = thread(target=self._handle_flow_down)
        self._flow_up_thread = thread(target=self._handle_flow_up)

    def entry_point_flow_down(self, stream: list[Packet]) -> None:
        # stream of packets to flow out enter the stack here (will travel down the stack)
        self._flow_down_queue.put(stream)

    def entry_point_flow_up(self, stream: list[Packet]) -> None:
        # stream of packets to flow in enter the stack here (will travel up the stack)
        self._flow_up_queue.put(stream)

    def _handle_flow_up(self) -> None:
        # threaded method that manages packets flowing up the stack
        while True:
            stream: Optional[list[Packet]] = self._flow_up_queue.get()
            if stream is None:
                break

            # flow the packet up the stack to handle packet decryption etc., then flow it back down for the next hop
            self._flow_up(stream)
            self._flow_down_queue.put(stream)
            self._flow_up_queue.task_done()

        self._flow_up_queue.task_done()
        self._flow_up_thread.join()

    def _handle_flow_down(self) -> None:
        # threaded method that manages packets flowing down the stack
        while True:
            stream: Optional[list[Packet]] = self._flow_down_queue.get()
            if stream is None:
                break

            # flow the packet down the stack to handle packet encryption etc.
            self._flow_down(stream)
            self._flow_down_queue.task_done()

        self._flow_down_queue.task_done()
        self._flow_down_queue.join()

    def _flow_down(self, stream: list[Packet]):

        self._level6_presentation(stream, stack_direction.down)
        # level5_session
        # level4_transport
        # level3_network

        self._packet_injector.inject_stream(stream)

    def _level6_presentation(self, stream: list[Packet], direction: stack_direction):
        if direction == stack_direction.down:
            if self._is_client:

                # apply symmetric encryption and kmac to each packet individually
                for layer in range(self._relay_node_layers):
                    # TODO : layer6_presentation.add_next_hop_ip(stream, [])
                    layer6_presentation.symmetric_encrypt_stream_payloads(stream, self._packet_symmetric_encryption_keys[layer], self._packet_symmetric_encryption_ivs[layer])
                    layer6_presentation.kmac_append_to_stream_payloads(stream, self._packet_kmac_keys[layer])


            """ASYMMETRIC CONNECTION SIGNATURE"""

            # generate signature from the entire stream (post individual packet encryption)
            concatenated_payloads           = b"".join([packet.payload for packet in stream])
            concatenated_payloads_signature = layer6_presentation.sign_payload(concatenated_payloads, self._connection_asymmetric_signature_key)

            # chunk the signature into equal lengths (amount of chunks = number of packets in stream)
            chunked_payloads_signature_lengths = ceil(len(concatenated_payloads_signature) / len(stream))
            chunked_payloads_signature_chunks  = [concatenated_payloads_signature[i : i + chunked_payloads_signature_lengths] for i in range(0, len(concatenated_payloads_signature), chunked_payloads_signature_lengths)]

            # append each signature chunk to the corresponding packet (by index)
            for chunked_payloads_signature_chunk, packet in zip(chunked_payloads_signature_chunks, stream):
                packet.payload += layer6_presentation.separator + chunked_payloads_signature_chunk

            """ASYMMETRIC CONNECTION ENCRYPTION"""

            # encrypt the entire stream (including the added signature chunks) and re-splice to original payload lengths
            concatenated_payloads             = b"".join([packet.payload for packet in stream])
            concatenated_payloads_encrypted   = symmetric_cipher.encrypt(concatenated_payloads, self._connection_symmetric_encryption_key, self._connection_symmetric_encryption_iv)

            # split the encrypted stream back into the original packet sizes
            chunked_payloads_encrypted_lengths = [len(packet.payload) for packet in stream]
            chunked_payloads_encrypted_chunks = b"".join(islice(iter(concatenated_payloads_encrypted), i) for i in chunked_payloads_encrypted_lengths)

            # set the packet payloads to the spliced connection encrypted stream packet payload
            for chunked_payloads_encrypted_chunk, packet in zip(chunked_payloads_encrypted_chunks, stream):
                packet.payload = chunked_payloads_encrypted_chunk

            """ASYMMETRIC CONNECTION MAC"""

            # generate mac for entire stream (post connection encryption)
            concatenated_payloads      = b"".join([packet.payload for packet in stream])
            concatenated_payloads_mac = message_authentication_codes.generate_tag(concatenated_payloads)

            # chunk the mac into equal lengths (amount of chunks = number of packets in stream)
            chunked_payloads_mac_lengths = ceil(len(concatenated_payloads_mac) / len(stream))
            chunked_payloads_mac_chunks  = [concatenated_payloads_mac[i : i + chunked_payloads_mac_lengths] for i in range(0, len(concatenated_payloads_mac), chunked_payloads_mac_lengths)]

            # append each kmac chunk to the corresponding packet (by index)
            for chunked_payloads_mac_chunk, packet in zip(chunked_payloads_mac_chunks, stream):
                packet.payload += layer6_presentation.separator + chunked_payloads_mac_chunk

        elif direction == stack_direction.up:

            """ASYMMETRIC CONNECTION MAC"""

            # capture and remove kmac from each packet
            chunked_packet_kmac_chunks = []
            for packet in stream:
                chunked_packet_kmac_chunks.append(packet.payload[packet.payload.find(layer6_presentation.separator) + 1:])
                packet.payload = packet.payload[:packet.payload.find(layer6_presentation.separator)]

            # regenerate mac from payload and compare it against received mac
            concatenated_payloads = b"".join([packet.payload for packet in stream])
            concatenated_payloads_mac = message_authentication_codes.generate_tag()
