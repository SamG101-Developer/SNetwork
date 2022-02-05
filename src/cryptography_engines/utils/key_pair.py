from typing import Optional


class key_pair:
    def __init__(self, secret_key: Optional[bytes] = None, public_key: Optional[bytes] = None):
        self._secret_key: Optional[bytes] = secret_key
        self._public_key: Optional[bytes] = public_key

    @property
    def public_key(self) -> Optional[bytes]:
        return self._public_key

    @property
    def secret_key(self) -> Optional[bytes]:
        return self._secret_key
