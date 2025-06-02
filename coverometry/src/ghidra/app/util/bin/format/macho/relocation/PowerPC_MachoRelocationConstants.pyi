import java.lang


class PowerPC_MachoRelocationConstants(object):
    PPC_RELOC_BR14: int = 2
    PPC_RELOC_BR24: int = 3
    PPC_RELOC_HA16: int = 6
    PPC_RELOC_HA16_SECTDIFF: int = 12
    PPC_RELOC_HI16: int = 4
    PPC_RELOC_HI16_SECTDIFF: int = 10
    PPC_RELOC_JBSR: int = 13
    PPC_RELOC_LO14: int = 7
    PPC_RELOC_LO14_SECTDIFF: int = 14
    PPC_RELOC_LO16: int = 5
    PPC_RELOC_LO16_SECTDIFF: int = 11
    PPC_RELOC_LOCAL_SECTDIFF: int = 15
    PPC_RELOC_PAIR: int = 1
    PPC_RELOC_PB_LA_PTR: int = 9
    PPC_RELOC_SECTDIFF: int = 8
    PPC_RELOC_VANILLA: int = 0



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

