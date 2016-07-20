"""QUIC protocol implementation."""

import collections
from functools import partial
from operator import add
from typing import Tuple

from functional import seq


class HandshakeMessage:
    """Crypto handshake message."""
    tag = None # type: bytes
    tag_count = 0
    tags = collections.OrderedDict() # type: collections.OrderedDict


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


def decode_handshake_message(raw_data: bytes) -> HandshakeMessage:
    """
    Args:
        raw_data: QUIC message without public header.
    """
    msg = HandshakeMessage()
    msg.tag = raw_data[:4]
    msg.tag_count = (raw_data[5] << 8) | raw_data[4]

    values_start_pos = 8 + msg.tag_count * 8
    value_positions = seq(values_start_pos) + tag_positions(msg.tag_count)\
        .map(lambda pos: int32_little_endian(pos + 4, raw_data))\
        .map(partial(add, values_start_pos))

    msg.tags = tag_positions(msg.tag_count)\
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
