import java.lang


class FdtConstants(object):
    FDT_BEGIN_NODE: int = 1
    FDT_END: int = 9
    FDT_END_NODE: int = 2
    FDT_MAGIC: int = -804389139
    FDT_MAGIC_BYTES: List[int] = array('b', [-48, 13, -2, -19])
    FDT_MAGIC_SIZE: int = 4
    FDT_NOP: int = 4
    FDT_PROP: int = 3
    FDT_TAGSIZE: int = 4
    FDT_V16_SIZE: int = 36
    FDT_V17_SIZE: int = 40
    FDT_V1_SIZE: int = 28
    FDT_V2_SIZE: int = 32
    FDT_V3_SIZE: int = 36
    FDT_VERSION_1: int = 1
    FDT_VERSION_16: int = 16
    FDT_VERSION_17: int = 17
    FDT_VERSION_2: int = 2
    FDT_VERSION_3: int = 3



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

