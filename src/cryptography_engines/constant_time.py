from cryptography.hazmat.primitives.constant_time import bytes_eq


class constant_time:
    """
    constant time functions are implements to avoid timing attacks (side channel attacks) and to decrease the rate of
    information leakage
    """

    @staticmethod
    def is_equal(left: bytes, right: bytes):
        # check if two values are equal (in constant time)
        return bytes_eq(left, right)

    @staticmethod
    def is_not_equal(left: bytes, right: bytes):
        # check if two values are not equal (in constant time)
        return not constant_time.is_equal(left, right)
