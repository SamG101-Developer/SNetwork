from time import time
from numpy import linspace
from struct import pack

from .hashing import hashing


class timestamps:
    TOLERANCE: int = 2

    @staticmethod
    def generate_timestamp() -> int:
        return int(time())

    @staticmethod
    def generate_hashed_timestamp() -> bytes:
        return hashing.hash(timestamps.encode_timestamp(timestamps.generate_timestamp()))

    @staticmethod
    def is_in_tolerance(hash_to_match: bytes) -> bool:
        now = timestamps.generate_timestamp()
        return any([hashing.hash(timestamps.encode_timestamp(now + i)) == hash_to_match] for i in range(0, timestamps.TOLERANCE))

    @staticmethod
    def encode_timestamp(timestamp: int):
        return pack("f", timestamp)
