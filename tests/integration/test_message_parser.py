from hamcrest import assert_that, is_, has_entries

import quic.handshake as handshake
from quic.handshake import read_packet, decode_handshake_message


def fixture_packet(fixture_name):
    return read_packet('tests/integration/fixtures/{}.raw'.format(fixture_name))


def describe_decode_handhsake_message():
    def it_parses_raw_data_and_returns_handshake_message_object():
        msg = decode_handshake_message(fixture_packet('chlo')[30:])

        assert_that(msg.tag, is_(b'CHLO'))
        assert_that(msg.tag_count, is_(15))

        expected_tags = {
            'SNI': b'www.example.com',
            'VER': b'Q035',
            'CCS': b'\x7b\x26\xe9\xe7\xe4\x5c\x71\xff\x01\xe8\x81\x60\x92\x92\x1a\xe8',
            'MSPC': b'\x64\x00\x00\x00',
            'PDMD': b'\x58\x35\x30\x39',
            'ICSL': b'\x58\x02\x00\x00',
            'CTIM': b'\x36\xca\x83\x57\x00\x00\x00\x00',
            'NONP': b'\x6a\x74\x93\x6a\xae\x83\xce\xdb\xcf\x1a\xec\x7e\x35'\
                b'\x16\xb5\xaa\xfb\x66\x41\x0c\x34\xaa\xc6\xb8\x82\xa0\x53'\
                b'\xa2\xe3\x4c\x3b\x93',
            'MIDS': b'\x64\x00\x00\x00',
            'SCLS': b'\x01\x00\x00\x00',
            'CSCT': b'',
            'COPT': b'\x46\x49\x58\x44',
            'CFCW': b'\x00\x40\x00\x00',
            'SFCW': b'\x00\x40\x00\x00',
        }
        assert_that(msg.tags, has_entries(expected_tags))

    def it_is_able_to_parse_message_serialized_with_to_bytes():
        msg = handshake.Message()
        msg.tag = b'CHLO'
        msg.tags = {'SNI': 'www.example.com', 'VER': 'Q034'}

        deserialized_msg = decode_handshake_message(msg.to_bytes())

        assert_that(deserialized_msg.tag, is_(b'CHLO'))
        assert_that(
            deserialized_msg.tags,
            has_entries({'SNI': b'www.example.com', 'VER': b'Q034'})
        )
