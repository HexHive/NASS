import java.lang


class X86_64_MachoRelocationConstants(object):
    X86_64_RELOC_BRANCH: int = 2
    X86_64_RELOC_GOT: int = 4
    X86_64_RELOC_GOT_LOAD: int = 3
    X86_64_RELOC_SIGNED: int = 1
    X86_64_RELOC_SIGNED_1: int = 6
    X86_64_RELOC_SIGNED_2: int = 7
    X86_64_RELOC_SIGNED_4: int = 8
    X86_64_RELOC_SUBTRACTOR: int = 5
    X86_64_RELOC_TLV: int = 9
    X86_64_RELOC_UNSIGNED: int = 0



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

