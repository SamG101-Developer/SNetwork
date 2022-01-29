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

from pydivert.packet import Packet


class custom_tcp_stack:
    def __init__(self, is_client=False):
        self._packet_injector = packet_injector(self)
        self._packet_interceptor = packet_interceptor(self)

        if is_client:
            self._relay_node_layers = 3

            self._packet_symmetric_encryption_ivs = []
            self._packet_symmetric_encryption_keys = []
            self._packet_kmac_keys = []

            self._connection_symmetric_encryption_iv  = iv_context(urandom(16))  # one time use so can be random
            self._connection_symmetric_encryption_key = b""
            self._connection_asymmetric_signature_key = b""
            self._connection_kmac_key = b""

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
        # apply symmetric encryption and kmac to each packet individually
        for layer in range(self._relay_node_layers):
            layer6_presentation.symmetric_encrypt_stream_payloads(stream, self._packet_symmetric_encryption_keys[layer], self._packet_symmetric_encryption_ivs[layer])
            layer6_presentation.kmac_append_to_stream_payloads(stream, self._packet_kmac_keys[layer])

        # generate signature from the entire stream (post individual packet encryption)
        concatenated_payloads           = b"".join([packet.payload for packet in stream])
        concatenated_payloads_signature = layer6_presentation.sign_payload(concatenated_payloads, self._connection_asymmetric_signature_key)

        # chunk the signature into equal lengths (amount of chunks = number of packets in stream)
        chunked_payloads_signature_lengths = ceil(len(concatenated_payloads_signature) / len(stream))
        chunked_payloads_signature_chunks  = [concatenated_payloads_signature[i : i + chunked_payloads_signature_lengths] for i in range(0, len(concatenated_payloads_signature), chunked_payloads_signature_lengths)]

        # append each signature chunk to the corresponding packet (by index)
        for chunked_payloads_signature_chunk, packet in zip(chunked_payloads_signature_chunks, stream):
            packet.payload += chunked_payloads_signature_chunk

        # encrypt the entire stream (including the added signature chunks)
        current_payload_lengths = [len(packet.payload) for packet in stream]

        concatenated_payloads             = b"".join([packet.payload for packet in stream])
        concatenated_payloads_encrypted   = symmetric_cipher.encrypt(concatenated_payloads, self._connection_symmetric_encryption_key, self._connection_symmetric_encryption_iv)
        chunked_payloads_encrypted_chunks = b"".join(islice(iter(concatenated_payloads_encrypted), i) for i in current_payload_lengths)
        for chunked_payloads_encrypted_chunk, packet in zip(chunked_payloads_encrypted_chunks, stream):
            packet.payload = chunked_payloads_encrypted_chunk

        # generate kmac for entire stream (post connection encryption)
        concatenated_payloads = b"".join([packet.payload for packet in stream])
        concatenated_payloads_kmac = message_authentication_codes.generate_tag(concatenated_payloads)

        # chunk the kmac into equal lengths (amount of chunks = number of packets in stream)
        chunked_payloads_kmac_lengths = ceil(len(concatenated_payloads_kmac) / len(stream))
        chunked_payloads_kmac_chunks  = [concatenated_payloads_kmac[i : i + chunked_payloads_kmac_lengths] for i in range(0, len(concatenated_payloads_kmac), chunked_payloads_kmac_lengths)]

        # append each kmac chunk to the corresponding packet (by index)
        for chunked_payloads_kmac_chunk, packet in zip(chunked_payloads_kmac_chunks, stream):
            packet.payload += chunked_payloads_kmac_chunk

        # level5_session
        # level4_transport
        # level3_network

        self._packet_injector.inject_stream(stream)
