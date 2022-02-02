import os
import socket
import ssl

from .layer7_application import connection_commands
from ...cryptography_engines.asymmetric_signature import asymmetric_signature
from ...cryptography_engines.asymmetric_key_encapsulation_mechanism import asymmetric_key_encapsulation_mechanism
from ...cryptography_engines.hash_algorithm import hash_algorithm


def initialize_connection_between_nodes(self, next_hop_address: str, my_static_private_key: bytes):
    # send a connection request
    connection = socket.socket()
    connection.connect((next_hop_address, 666))
    connection.send(connection_commands.k_connection_initialization_request)

    # listen for a connection confirm
    if connection.recv(1) == connection_commands.k_connection_initialization_confirm:

        # get the static public key for verification and the ephemeral public key for kem
        next_hop_static_public_key           = b""  # TODO : from PKI in DHT
        next_hop_ephemeral_public_key_signed = connection.recv(asymmetric_signature.PUBLIC_KEY_LENGTH + asymmetric_signature.SIGNATURE_LENGTH)

        # check that the verification is correct on the ephemeral public key
        if asymmetric_signature.verify_signature(
            next_hop_static_public_key,
            next_hop_ephemeral_public_key_signed[:asymmetric_signature.PUBLIC_KEY_LENGTH],
            next_hop_ephemeral_public_key_signed[:-asymmetric_signature.SIGNATURE_LENGTH]):

            random_symmetric_master_key = os.urandom(128)
            signed_random_symmetric_master_key = random_symmetric_master_key + asymmetric_signature.sign_message(
                my_static_private_key,
                hash_algorithm.hashing(random_symmetric_master_key))

            encrypted_signed_random_symmetric_master_key = asymmetric_key_encapsulation_mechanism.
