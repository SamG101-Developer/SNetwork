# from cryptography_engines.signing import signing
# from cryptography_engines.kem import kem
#
#
# class relay_node(_node):
#     HOP_COUNT = 1
#
#     def __init__(self):
#         _node.__init__(self)
#
#         my_static_secret_key, my_static_public_key = signing.import_keypair("TODO")
#         my_ephemeral_public_key = self._my_ephemeral_kex_keys[0][1]
#         self._signed_ephemeral_public_key = signing.sign_message(my_static_secret_key, my_ephemeral_public_key)
#
#         self._clients_ephemeral_public_key = None
#
#     def load_clients_ephemeral_public_key(self, encapsulated_clients_ephemeral_public_key):
#         my_ephemeral_key_pair = self._my_ephemeral_kex_keys[0]
#         self._clients_ephemeral_public_key = kem.decrypt_kem(*my_ephemeral_key_pair, encapsulated_clients_ephemeral_public_key)
#         self._compute_kem_shared_secrets()
#
#     def _compute_kem_shared_secrets(self) -> None:
#         pass
#
#
class relay_node_info:
    ip: str
    ephemeral_public_key: bytes
