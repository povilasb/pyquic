"""Packet parsing and construction utilities."""

from functools import reduce
from typing import Tuple

import fnv


PUBLIC_FLAG_VERSION = 0x01
PUBLIC_FLAG_RESET = 0x02
PUBLIC_FLAG_DIVERSIFICATION_NONCE = 0x04
PUBLIC_FLAG_CONNECTION_ID_8_BYTES = 0x08
PUBLIC_FLAG_PACKET_NUMBER_1_BYTE = 0x00
PUBLIC_FLAG_PACKET_NUMBER_2_BYTE = 0x10
PUBLIC_FLAG_PACKET_NUMBER_4_BYTE = 0x20
PUBLIC_FLAG_PACKET_NUMBER_6_BYTE = 0x30

PACKET_HASH_SIZE = 12 # bytes


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

    def to_bytes(self) -> bytes:
        """Serializes public header to bytes array."""
        return self.public_flags.to_bytes(1, byteorder='little') \
            + self.connection_id.to_bytes(8, byteorder='little') \
            + self.protocol_version \
            + self.packet_number.to_bytes(1, byteorder='little')
        # TODO: get the actual packet number field length


class StreamFrameHeader:
    id = 0
    finish = False
    has_data_length = False
    data_length = 0
    offset_length = 0
    id_length = 0



class Parser:
    """QUIC packet parser."""

    def __init__(self, data: bytes) -> None:
        """
        Args:
            data: UDP datagram.
        """
        self.data = data
        self.data_offset = 0
        self.packet_hash_offset = 0

    def parse_public_header(self) -> PublicHeader:
        """Advances data offset pointer.

        Restarts data offset to 0 and advances it to point just after the
        public header.
        """
        header = PublicHeader()
        header.public_flags = self.data[0]
        header.connection_id = self.data[1:9]
        header.protocol_version = self.data[9:13]
        header.packet_number = self._parse_packet_number(
            13, header.packet_number_length)

        self.data_offset = 13 + header.packet_number_length

        return header

    def parse_packet_hash(self) -> int:
        """Extracts packet hash starting from the current data buffer offset.

        QUIC packet hash is 12 bytes long little endian encoded integer number.

        Returns:
            Extracted hash integer.
        """
        self.packet_hash_offset = self.data_offset
        self.data_offset += PACKET_HASH_SIZE

        return int.from_bytes(
            self.data[self.packet_hash_offset:
                self.packet_hash_offset + PACKET_HASH_SIZE],
            'little'
        )

    def parse_stream_frame_header(self) -> StreamFrameHeader:
        header = StreamFrameHeader()

        frame_type_byte = self.data[self.data_offset]
        header.finish = bool(frame_type_byte & 0x40)
        header.has_data_length = bool(frame_type_byte & 0x20)

        header.offset_length = (frame_type_byte >> 2) & 7
        if header.offset_length:
            header.offset_length += 1

        header.id_length = (frame_type_byte & 3) + 1
        header.id = int.from_bytes(
            self.data[self.data_offset + 1\
                :self.data_offset + 1 + header.id_length],
            'little'
        )

        self.data_offset += 1 + header.id_length + header.offset_length

        return header

    def calc_packet_hash(self) -> int:
        """Calculates packet hash.

        FNV-1a algorithm is used to hash the packet content.

        Returns:
            96 bit packet hash.
        """
        self._ensure_packet_hash_offset_is_set()
        without_hash = bytes_excluded(self.data, self.packet_hash_offset,
            PACKET_HASH_SIZE)
        return fnv.ensure_bits_count(
            fnv.hash(without_hash), PACKET_HASH_SIZE * 8)

    def _parse_packet_number(self, data_offset:int,
            packet_number_length: int) -> int:
        """Parses packet number starting from the current data offset."""
        return int.from_bytes(
            self.data[data_offset:data_offset + packet_number_length],
            'little'
        )

    def _ensure_packet_hash_offset_is_set(self):
        """
        Throws:
            PacketHashNotFound: if packet hash offset is not set.
        """
        if not self.packet_hash_offset:
            raise IndexError('Packet hash offset was not set. ' \
                'Be sure to parse packet hash before calling this function.')


def frame_type(frame_type_byte: int) -> str:
    """Identifies frame type from frame type byte."""
    if frame_type_byte >> 7 == 1:
        return 'STREAM'


def bytes_excluded(data: bytes, start: int, length: int) -> bytes:
    """Excludes the specified bytes region and returns what's left."""
    return data[:start] + data[start + length:]
