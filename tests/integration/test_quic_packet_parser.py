from hamcrest import assert_that, is_, has_entries

from quic.packet import Parser
from quic.proto import read_packet


def fixture_packet(fixture_name):
    return read_packet('tests/integration/fixtures/{}.raw'.format(fixture_name))


def describe_parser():
    def describe_calc_packet_hash():
        def describe_when_packet_hash_was_parsed():
            parser = Parser(fixture_packet('chlo_q034'))
            parser.parse_public_header()
            parser.parse_packet_hash()

            def it_calculates_12_byte_hash_value():
                packet_hash = parser.calc_packet_hash()

                assert_that(packet_hash, is_(0xda4e6a9c4b3af51927e22fdc))
