import java.lang


class AARCH64_MachoRelocationConstants(object):
    ARM64_RELOC_ADDEND: int = 10
    ARM64_RELOC_AUTHENTICATED_POINTER: int = 11
    ARM64_RELOC_BRANCH26: int = 2
    ARM64_RELOC_GOT_LOAD_PAGE21: int = 5
    ARM64_RELOC_GOT_LOAD_PAGEOFF12: int = 6
    ARM64_RELOC_PAGE21: int = 3
    ARM64_RELOC_PAGEOFF12: int = 4
    ARM64_RELOC_POINTER_TO_GOT: int = 7
    ARM64_RELOC_SUBTRACTOR: int = 1
    ARM64_RELOC_TLVP_LOAD_PAGE21: int = 8
    ARM64_RELOC_TLVP_LOAD_PAGEOFF12: int = 9
    ARM64_RELOC_UNSIGNED: int = 0



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

