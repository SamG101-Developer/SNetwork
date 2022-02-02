from hmac import new as hmac

from .hashing import algorithm as hash_algorithm


class mac:
    TAG_LENGTH = 32

    @staticmethod
    def generate_tag(data: bytes, key: bytes) -> bytes:
        return hmac(key, data, hash_algorithm).digest()[:mac.TAG_LENGTH]
