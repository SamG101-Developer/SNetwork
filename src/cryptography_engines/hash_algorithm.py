from hashlib import sha3_512 as algorithm
from whirlpool import new as _algorithm


class hash_algorithm:

    @staticmethod
    def hash(data: bytes):
        return algorithm(data).digest()
