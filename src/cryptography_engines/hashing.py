from hashlib import sha3_512 as algorithm


class hashing:
    """
    collection of hashing functions acting as syntactic sugar
    """

    # length of the hash-digest prior to encoding (ie with base58 etc...)
    HASH_LENGTH = algorithm().digest_size

    @staticmethod
    def hash(data: bytes, encoding=bytes):
        # hash a byte-string and map it into an encoding
        return encoding(algorithm(data).digest())
