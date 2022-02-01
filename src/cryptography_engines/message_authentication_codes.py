from hashlib import shake_256
from hmac import new as hmac


class message_authentication_codes:

    @staticmethod
    def generate_tag(data: bytes, key: bytes) -> bytes:
        return hmac(key, data, shake_256).digest()
