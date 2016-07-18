from hamcrest import assert_that, is_
import pytest

from quic.packet import PublicHeader, PUBLIC_FLAG_VERSION, \
    PUBLIC_FLAG_PACKET_NUMBER_1_BYTE, PUBLIC_FLAG_PACKET_NUMBER_2_BYTE, \
    PUBLIC_FLAG_PACKET_NUMBER_4_BYTE, PUBLIC_FLAG_PACKET_NUMBER_6_BYTE, \
    parse_public_header, parse_packet_hash


def describe_public_header():
    def describe_constructor():
        def describe_when_default_values_are_used():
            def it_initialises_flags_so_that_version_field_is_set_connection_id_is_8_bytes_diversification_nonce_is_used_and_packet_number_is_1_byte():
                header = PublicHeader()

                assert_that(header.public_flags, is_(0x0d))

    def describe_version_set():
        @pytest.mark.parametrize('flags, expected_value', [
            (0, False),
            (PUBLIC_FLAG_VERSION, True),
        ])
        def it_returns_boolean_value_if_version_flag_is_set_or_not(
                flags, expected_value):
            header = PublicHeader()
            header.public_flags = flags

            assert_that(header.has_version, is_(expected_value))

    def describe_packet_number_length():
        @pytest.mark.parametrize('flags, expected_length', [
            (PUBLIC_FLAG_PACKET_NUMBER_1_BYTE, 1),
            (PUBLIC_FLAG_PACKET_NUMBER_2_BYTE, 2),
            (PUBLIC_FLAG_PACKET_NUMBER_4_BYTE, 4),
            (PUBLIC_FLAG_PACKET_NUMBER_6_BYTE, 6),
        ])
        def it_returns_how_many_bytes_packet_number_takes_according_to_public_flags(
                flags, expected_length):
            header = PublicHeader()
            header.public_flags = flags

            assert_that(header.packet_number_length, is_(expected_length))

def describe_parse_public_header():
    def it_extracts_public_flags():
        data = b'\x08\x01\x02\x03\x04\x05\x06\x07\x08......'

        header = parse_public_header(data)

        assert_that(header.public_flags, is_(0x08))

    def it_extracts_connection_id():
        data = b'\x08\x01\x02\x03\x04\x05\x06\x07\x08......'

        header = parse_public_header(data)

        assert_that(header.connection_id, is_(b'\x01\x02\x03\x04\x05\x06\x07\x08'))

    def it_extracts_protocol_version():
        data = b'\x08\x01\x02\x03\x04\x05\x06\x07\x08Q025...'

        header = parse_public_header(data)

        assert_that(header.protocol_version, is_(b'Q025'))

    def describe_when_packet_number_is_1_byte_long():
        def it_extracts_this_one_byte_as_packet_number():
            data = b'\x08\x01\x02\x03\x04\x05\x06\x07\x08Q025\x12...'

            header = parse_public_header(data)

            assert_that(header.packet_number, is_(0x12))

    def describe_when_packet_number_is_more_than_1_byte_long():
        def it_extracts_those_bytes_in_little_endian_order():
            data = b'\x18\x01\x02\x03\x04\x05\x06\x07\x08Q025\x34\x12...'

            header = parse_public_header(data)

            assert_that(header.packet_number, is_(0x1234))

def describe_parse_packet_hash():
    def it_extracts_12_byte_hash_in_little_endian_encoding():
        data = b'....\x12\x11\x10\x09\x08\x07\x06\x05\x04\x03\x02\x01....'
        offset = 4

        packet_hash = parse_packet_hash(data, offset)

        assert_that(packet_hash, is_(0x010203040506070809101112))
