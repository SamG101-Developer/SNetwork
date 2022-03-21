from enum import Enum


class connection_protocol(Enum):
    REQUEST_CONNECTION = 0  # Request a connection to a another node
    ACCEPT_CONNECTION = 1  # Accept a connection from another node
    REJECT_CONNECTION = 2  # Reject a connection to another node

    KEX_INIT = 3  # Initialize a key exchange (signed ephemeral public key)
    NEW_KEY = 4  # Change the AES key with a key wrap
