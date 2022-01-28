import argon2 as algorithm


class key_derivation_function:

    @staticmethod
    def generate_tag(data: bytes, salt: bytes, tag_length: int) -> bytes:
        return algorithm.hash_password_raw(password=data, salt=salt, hash_len=tag_length)
