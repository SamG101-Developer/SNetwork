from enum import Enum


class packet_flags:
    FLAG_LENGTH: int = 8

    IPV4 = 0x01
    IPV6 = 0x02
