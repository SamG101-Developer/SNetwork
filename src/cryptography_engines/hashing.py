from hashlib import sha3_512 as algorithm


class hashing:
    HASH_LENGTH = algorithm.digest_size

    @staticmethod
    def hash(data: bytes, encoding=bytes):
        return encoding(algorithm(data).digest())
