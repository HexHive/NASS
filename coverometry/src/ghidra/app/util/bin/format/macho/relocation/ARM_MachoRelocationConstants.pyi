import java.lang


class ARM_MachoRelocationConstants(object):
    ARM_RELOC_BR24: int = 5
    ARM_RELOC_HALF: int = 8
    ARM_RELOC_HALF_SECTDIFF: int = 9
    ARM_RELOC_LOCAL_SECTDIFF: int = 3
    ARM_RELOC_PAIR: int = 1
    ARM_RELOC_PB_LA_PTR: int = 4
    ARM_RELOC_SECTDIFF: int = 2
    ARM_RELOC_VANILLA: int = 0
    ARM_THUMB_32BIT_BRANCH: int = 7
    ARM_THUMB_RELOC_BR22: int = 6



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

