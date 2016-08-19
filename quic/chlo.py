"""QUIC client hello (CHLO) message related utilities."""

import random
import time
from collections import OrderedDict

import fnv

from quic.packet import PublicHeader, StreamFrameHeader
import quic.handshake as handshake
import quic.tags as tags


VERSION = 'Q034'


def make_message() -> bytes:
    pub_header = PublicHeader()
    pub_header.protocol_version = bytes(VERSION, 'ascii')
    pub_header.packet_number = 1
    pub_header.connection_id = random.randint(0, 0xffffffffffffffff)

    chlo_msg = handshake.Message()
    chlo_msg.tag = b'CHLO'
    chlo_msg.tags = tags.Container({
        'VER': VERSION, 'PDMD': 'X509',
        'PAD': b'\x00' * 1000
    })
    chlo_msg_buff = chlo_msg.to_bytes()

    stream_header = StreamFrameHeader()
    stream_header.id = 1
    stream_header.has_data_length = True
    stream_header.data_length = len(chlo_msg_buff)
    # TODO: infer id length from id field.
    stream_header.id_length = 1

    pub_header_buff = pub_header.to_bytes()
    stream_header_buff = stream_header.to_bytes()
    padding = b'\x00' * (1300 - (len(pub_header_buff) + 12 \
        + len(stream_header_buff) + len(chlo_msg_buff)))
    packet_hash = fnv.hash(pub_header_buff + stream_header_buff + chlo_msg_buff + padding)

    return pub_header_buff + packet_hash.to_bytes(16, byteorder='little')[:12] \
        + stream_header_buff + chlo_msg_buff + padding
