from hashlib import sha3_512 as algorithm


class hashing:
    @staticmethod
    def hash(data: bytes, encoding=bytes):
        return encoding(algorithm(data).digest())
