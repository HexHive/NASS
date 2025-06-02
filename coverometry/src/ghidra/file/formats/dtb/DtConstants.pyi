import java.lang


class DtConstants(object):
    DT_TABLE_DEFAULT_PAGE_SIZE: int = 2048
    DT_TABLE_DEFAULT_VERSION: int = 0
    DT_TABLE_MAGIC: int = -675828962
    DT_TABLE_MAGIC_BYTES: List[int] = array('b', [-41, -73, -85, 30])
    DT_TABLE_MAGIC_SIZE: int = 4



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

