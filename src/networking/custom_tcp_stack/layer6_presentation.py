from ...cryptography_engines.symmetric_cipher import cipher, iv_context
from ...cryptography_engines.message_authentication_codes import message_authentication_codes
from ...cryptography_engines.asymmetric_signature import asymmetric_signature
from ...cryptography_engines.hash_algorithm import hash_algorithm

from pydivert import Packet


class layer6_presentation:
    separator = "#"

    @staticmethod
    def symmetric_encrypt_stream_payloads(stream: list[Packet], key: bytes, iv: iv_context) -> None:
        for packet in stream:
            symmetric_encrypt_packet_payload(packet, key, iv)

    @staticmethod
    def symmetric_decrypt_stream_payloads(stream: list[Packet], key: bytes) -> None:
        for packet in stream:
            symmetric_decrypt_packet_payload(packet, key)

    @staticmethod
    def kmac_append_to_stream_payloads(stream: list[Packet], key: bytes) -> None:
        for packet in stream:
            kmac_append_to_payload(packet, key)

    @staticmethod
    def kmac_remove_from_stream_payloads(stream: list[Packet], key: bytes) -> None:
        for packet in stream:
            kmac_remove_from_payload(packet, key)

    @staticmethod
    def sign_payload(payload: bytes, key: bytes) -> bytes:
        return asymmetric_signature.sign_message(key, hash_algorithm.hashing(payload))


def symmetric_encrypt_packet_payload(packet: Packet, key: bytes, iv: iv_context) -> None:
    packet.payload = cipher.encrypt(packet.payload, key, iv)


def symmetric_decrypt_packet_payload(packet: Packet, key: bytes) -> None:
    packet.payload = cipher.decrypt(packet.payload, key)


def kmac_append_to_payload(packet: Packet, key: bytes) -> None:
    packet.payload += message_authentication_codes.generate_tag(packet.payload, key)


def kmac_remove_from_payload(packet: Packet, key: bytes) -> None:
    packet.payload, check_mac = packet.payload[:-64], packet.payload[-64:]
    assert message_authentication_codes.generate_tag(packet.payload, key) == check_mac
