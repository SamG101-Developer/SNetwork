import hkdf

from hashing import algorithm as hash_algorithm


class kdf:
    """
    key derivation functions are used to derive multiple keys from a master key, by using a hkdf-expand method with the
    hashing algorithm from the custom hashing module
    """

    @staticmethod
    def derive_key(master_key: bytes, customization: bytes, tag_length: int) -> bytes:
        # derive the key from the master bey by setting the customization string to the algorithm name for example
        return hkdf.hkdf_expand(master_key, customization, tag_length, hash_algorithm)
