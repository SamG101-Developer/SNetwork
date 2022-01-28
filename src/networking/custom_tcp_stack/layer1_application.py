from enum import Enum


class connection_commands(Enum):
    k_connection_initialization_request   = 0x01
    k_connection_initialization_confirm   = 0x02
    k_sent_ephemeral_key_generated        = 0x04
    k_send_master_symmetric_key_under_kem = 0x08
    k_forward_to_next_node                = 0x10
