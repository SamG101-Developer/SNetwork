class ip:
    def __init__(self, ip_address: str):
        self._ip_string = ip_address

    def to_string(self) -> str:
        return self._ip_string

    def to_bytes(self) -> bytes:
        return b""  # TODO
