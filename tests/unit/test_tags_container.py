from hamcrest import assert_that, is_

import quic.tags as tags


def describe_tags_container():
    def describe__setitem__():
        def it_sets_tag_value_than_can_be_retrieved_later():
            msg_tags = tags.Container()
            msg_tags['TAG1'] = 'value1'

            assert_that(msg_tags['TAG1'], is_('value1'))

        def it_accepts_32_bit_ints_as_tag_values():
            msg_tags = tags.Container()
            msg_tags[0x01020304] = 'value1'

            assert_that(msg_tags[0x01020304], is_('value1'))

        def it_converts_string_keys_to_ints_in_little_endian_before_storing():
            msg_tags = tags.Container()
            msg_tags['1234'] = 'value1'

            assert_that(msg_tags[0x34333231], is_('value1'))

    def describe_items():
        def it_returns_items_in_the_ascending_order_by_tag_name_int_value():
            msg_tags = tags.Container()
            msg_tags['V'] = 'value1'
            msg_tags['P'] = 'value2'
            msg_tags['A'] = 'value3'

            stored_tags = [t for t, _ in msg_tags.items()]

            assert_that(stored_tags, is_([0x41, 0x50, 0x56]))

    def describe_keys():
        def it_returns_keys_in_the_ascending_order_by_tag_name_int_value():
            msg_tags = tags.Container()
            msg_tags['V'] = 'value1'
            msg_tags['P'] = 'value2'
            msg_tags['A'] = 'value3'

            stored_tags = [t for t in msg_tags.keys()]

            assert_that(stored_tags, is_([0x41, 0x50, 0x56]))

    def describe_values():
        def it_returns_values_in_ascending_order_by_tag_name():
            msg_tags = tags.Container()
            msg_tags['V'] = 'value1'
            msg_tags['P'] = 'value3'
            msg_tags['A'] = 'value2'

            stored_tag_values = [t for t in msg_tags.values()]

            assert_that(stored_tag_values, is_(['value2', 'value3', 'value1']))

    def describe_constructor():
        def describe_when_non_empty_dictionary_is_provided():
            def it_converts_dictionary_keys_into_ints_and_stores_the_values():
                msg_tags = tags.Container({'1': 'value1', '2': 'value2'})

                assert_that(msg_tags.items(),
                    is_([(0x31, 'value1'), (0x32, 'value2')]))
