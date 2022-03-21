from hmac import new as hmac

from hashing import algorithm as hash_algorithm
from constant_time import constant_time


class mac:
    TAG_LENGTH = 32

    @staticmethod
    def generate_tag(data: bytes, key: bytes) -> bytes:
        return hmac(key, data, hash_algorithm).digest()[:mac.TAG_LENGTH]

    @staticmethod
    def generate_tag_matches(data: bytes, key: bytes, tag_to_match_against: bytes) -> bool:
        return constant_time.is_equal(mac.generate_tag(data, key), tag_to_match_against)
