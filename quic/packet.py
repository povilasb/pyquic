"""Packet parsing and construction utilities."""

from functools import reduce


PUBLIC_FLAG_VERSION = 0x01
PUBLIC_FLAG_RESET = 0x02
PUBLIC_FLAG_DIVERSIFICATION_NONCE = 0x04
PUBLIC_FLAG_CONNECTION_ID_8_BYTES = 0x08
PUBLIC_FLAG_PACKET_NUMBER_1_BYTE = 0x00
PUBLIC_FLAG_PACKET_NUMBER_2_BYTE = 0x10
PUBLIC_FLAG_PACKET_NUMBER_4_BYTE = 0x20
PUBLIC_FLAG_PACKET_NUMBER_6_BYTE = 0x30


class PublicHeader:
    """Public QUIC packet header."""

    def __init__(self):
        self.public_flags = PUBLIC_FLAG_VERSION \
            | PUBLIC_FLAG_CONNECTION_ID_8_BYTES \
            | PUBLIC_FLAG_DIVERSIFICATION_NONCE \
            | PUBLIC_FLAG_PACKET_NUMBER_1_BYTE
        self.connection_id = b''
        self.protocol_version = b'Q035'
        self.diversification_nonces = []
        self.packet_number = 0

    @property
    def has_version(self) -> bool:
        """Checks if public header has version field."""
        return (self.public_flags & PUBLIC_FLAG_VERSION) > 0

    @property
    def packet_number_length(self) -> int:
        """
        Returns:
            how many bytes are allocated to represent packet number.
        """
        length = 2 * (self.public_flags & 0x30) >> 4
        if not length:
            return 1
        return length


def parse_packet_number(data: bytes, offset: int,
        packet_number_length: int) -> int:
    """Parses packet number starting from the given offset."""
    return reduce(lambda nr, byte: (nr << 8) | byte,
        reversed(data[offset:offset + packet_number_length]), 0)


def parse_public_header(data: bytes) -> PublicHeader:
    """Parses public header from UDP datagram payload."""
    header = PublicHeader()
    header.public_flags = data[0]
    header.connection_id = data[1:9]
    header.protocol_version = data[9:13]
    header.packet_number = parse_packet_number(
        data, 13, header.packet_number_length)
    return header
