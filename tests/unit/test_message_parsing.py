from hamcrest import assert_that, is_, has_length

from quic.handshake import tag_at, int32_little_endian, tag_positions


def describe_tag_at():
    def it_returns_string_of_4_bytes_from_given_position():
        tag = tag_at(4, b'....MSPC...')

        assert_that(tag, is_('MSPC'))

    def describe_when_last_tag_bytes_are_zeroes():
        def it_removes_bytes_with_value_0():
            tag = tag_at(4, b'....VER\x00...')

            assert_that(tag, is_('VER'))

def describe_int32_little_endian():
    def it_decodes_32_bit_integer_from_given_buffer():
        number = int32_little_endian(4, b'....\x01\x02\x03\x04...')

        assert_that(number, is_(0x04030201))

def describe_tag_positions():
    def it_yields_as_much_positions_as_there_are_tags():
        positions = list(tag_positions(5))

        assert_that(positions, has_length(5))

    def it_yields_tag_positions_in_quic_message():
        positions = list(tag_positions(3))

        assert_that(positions, is_([8, 16, 24]))
