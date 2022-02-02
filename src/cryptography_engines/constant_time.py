from cryptography.hazmat.primitives.constant_time import bytes_eq


class constant_time:
    @staticmethod
    def is_equal(left: bytes, right: bytes):
        return bytes_eq(left, right)
