from cryptography.hazmat.primitives.constant_time import bytes_eq


class constant_time:
    @staticmethod
    def compare(left: bytes, right: bytes):
        return bytes_eq(left, right)
