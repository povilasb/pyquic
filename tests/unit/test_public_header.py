from hamcrest import assert_that, is_
import pytest

from quic.packet import PublicHeader, PUBLIC_FLAG_VERSION, \
    PUBLIC_FLAG_PACKET_NUMBER_1_BYTE, PUBLIC_FLAG_PACKET_NUMBER_2_BYTE, \
    PUBLIC_FLAG_PACKET_NUMBER_4_BYTE, PUBLIC_FLAG_PACKET_NUMBER_6_BYTE


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
