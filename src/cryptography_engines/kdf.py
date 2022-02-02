import hkdf

import hashing


class kdf:
    @staticmethod
    def derive_key(master_key: bytes, customization: bytes, tag_length: int):
        return hkdf.hkdf_expand(master_key, customization, tag_length, hashing.algorithm)
