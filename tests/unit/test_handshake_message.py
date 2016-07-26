from hamcrest import assert_that, is_

import quic.handshake as handshake


def describe_handshake_message():
    def describe_values_offset():
        def it_returns_offset_in_serialized_message_where_tag_values_start():
            msg = handshake.Message()
            msg.tag_count = 3

            assert_that(msg.values_offset, is_(32))

    def describe_to_bytes():
        def it_returns_bytes_array_starting_with_message_tag():
            msg = handshake.Message()
            msg.tag = b'CHLO'

            buff = msg.to_bytes()

            assert_that(buff[:4], is_(b'CHLO'))

        def it_returns_bytes_array_which_includes_tag_count_with_padding():
            msg = handshake.Message()
            msg.tag = b'CHLO'
            msg.tag_count = 0x01

            buff = msg.to_bytes()

            assert_that(buff[4:8], is_(b'\x01\x00\x00\x00'))

        def it_returns_bytes_array_with_tag_names_and_data_offsets_placed_after_tag_count():
            msg = handshake.Message()
            msg.tag = b'CHLO'
            msg.tag_count = 0x01
            msg.tags = {'SNI': 'www.example.com'}

            buff = msg.to_bytes()

            assert_that(buff[8:12], is_(b'SNI\x00'))
            assert_that(buff[12:16], is_(b'\x0f\x00\x00\x00'))

        def it_returns_bytes_array_with_tag_values_placed_after_tag_metainfo():
            msg = handshake.Message()
            msg.tag = b'CHLO'
            msg.tag_count = 0x01
            msg.tags = {'SNI': 'www.example.com'}

            buff = msg.to_bytes()

            assert_that(buff[16:31], is_(b'www.example.com'))
