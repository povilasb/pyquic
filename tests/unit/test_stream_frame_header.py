from hamcrest import assert_that, is_

from quic.packet import StreamFrameHeader


def describe_stream_frame_header():
    def describe_to_bytes():
        def it_returns_serialized_frame_header_to_bytes():
            header = StreamFrameHeader()
            header.finish = False
            header.has_data_length = True
            header.offset_length = 0
            header.data_length = 1300
            header.id_length = 1
            header.id = 1

            serialized = header.to_bytes()

            assert_that(serialized, is_(b'\xa0\x01\x14\x05'))
