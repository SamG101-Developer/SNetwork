from time import time
from numpy import linspace
from struct import pack

from .hashing import hashing


class timestamps:
    TOLERANCE: int = 1

    @staticmethod
    def generate_timestamp() -> float:
        return round(time(), 2)

    @staticmethod
    def generate_hashed_timestamp() -> bytes:
        return hashing.hash(pack("f", timestamps.generate_timestamp()))

    @staticmethod
    def is_in_tolerance(hash_to_match: bytes) -> bool:
        now = timestamps.generate_timestamp()
        return any([hashing.hash(pack("f", now + i)) == hash_to_match] for i in linspace(-timestamps.TOLERANCE, 1, 100 * timestamps.TOLERANCE + 1))
