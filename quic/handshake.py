"""QUIC handshake message utilities."""

import collections
from functools import partial, reduce
from operator import add
from typing import Tuple

from functional import seq


class Message:
    """Crypto handshake message."""
    tag = None # type: bytes
    tags = collections.OrderedDict() # type: collections.OrderedDict


    @property
    def tag_count(self) -> int:
        return len(self.tags)

    @property
    def values_offset(self) -> int:
        """
        Returns:
            tag values offset in serialized message buffer.
        """
        return 8 + self.tag_count * 8

    def to_bytes(self) -> bytes:
        """Serializes client handhsake message to bytes."""
        return self.tag + self.tag_count.to_bytes(2, byteorder='little') \
            + b'\x00\x00' + self._serialize_tags() + self._serialize_tag_values()

    def _serialize_tags(self):
        buff = b''
        value_end_offset = 0

        for tag, value in self.tags.items():
            value_end_offset += len(value)
            buff += serialize_tag(tag, value_end_offset)

        return buff

    def _serialize_tag_values(self):
        return reduce(lambda buff, tag_value: buff + serialize_tag_value(tag_value),
            self.tags.values(), b'')


def serialize_tag_value(tag_val) -> bytes:
    if type(tag_val) is str:
        return bytes(tag_val, 'ascii')
    elif type(tag_val) is bytes:
        return tag_val

    return None


def serialize_tag(tag: int, value_end_offset: int) -> bytes:
    """Serializes tag and it's value end offset.

    If tag is less than 4 bytes, it's padded with 0x00 bytes.
    """
    return tag.to_bytes(4, byteorder='little') \
        + value_end_offset.to_bytes(4, byteorder='little')


def tag_at(position: int, data: bytes) -> str:
    """Extracts tag at a given position."""
    return str(data[position:position + 4], 'ascii').strip('\x00')


def tag_value_at(start_end: Tuple[int, int], data: bytes) -> bytes:
    """Extracts tag value at the specified location in data buffer."""
    return data[start_end[0]:start_end[1]]


def int32_little_endian(position: int, data: bytes) -> int:
    """Decodes little endian encoded 32 bit integer."""
    return int.from_bytes(data[position:position + 4], 'little')


def tag_positions(tag_count: int):
    """Generates tag positions in QUIC message buffer."""
    return seq(range(0, tag_count)).map(lambda tag_nr: 8 + tag_nr * 8)


def decode_handshake_message(raw_data: bytes) -> Message:
    """
    Args:
        raw_data: QUIC message without public header.
    """
    msg = Message()
    msg.tag = raw_data[:4]

    tag_count = (raw_data[5] << 8) | raw_data[4]
    values_offset = 8 + tag_count * 8

    value_positions = seq(values_offset) + tag_positions(tag_count)\
        .map(lambda pos: int32_little_endian(pos + 4, raw_data))\
        .map(partial(add, values_offset))

    msg.tags = tag_positions(tag_count)\
        .map(partial(tag_at, data=raw_data))\
        .zip(value_positions\
            .zip(value_positions.drop(1))\
            .map(partial(tag_value_at, data=raw_data))
        )\
        .dict()

    return msg


def read_packet(fname: str) -> str:
    """Reads QUIC packet data from file.

    Used for debugging and testing.
    """
    with open(fname, 'rb') as f:
        return f.read()
