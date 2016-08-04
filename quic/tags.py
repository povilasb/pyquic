from collections import OrderedDict

from typing import Iterator, Union, List, Tuple


class Container(dict):
    """QUIC message tags container.

    It keeps tags ordered in increasing order by tag name.
    Which is a 32 bit number.
    """
    def __init__(self, init_tags: dict=None) -> None:
        if init_tags:
            for key, value in init_tags.items():
                self.__setitem__(key, value)

    def items(self) -> List[Tuple[int, bytes]]:
        """
        Returns:
            tags key value pairs sorted by tag in ascending order.
        """
        return sorted(super().items())

    def keys(self) -> List[int]:
        """
        Returns:
            tag sorted in ascending order.
        """
        return sorted(super().keys())

    def values(self) -> List[int]:
        """
        Returns:
            tag values sorted in ascending order by tag name.
        """
        return map(lambda key_val: key_val[1], self.items())

    def __setitem__(self, key: Union[str, int], value: str) -> None:
        super().__setitem__(_int_tag_name(key), value)

    def __getitem__(self, key: Union[str, int]) -> bytes:
        return super().__getitem__(_int_tag_name(key))


def _int_tag_name(tag: Union[str, int]) -> int:
    """Ensures that given tag name is integer.

    If it's not integer, it's converted to one.
    """
    if type(tag) == str:
        tag = int.from_bytes(bytes(tag, 'ascii'), byteorder='little')
    return tag
