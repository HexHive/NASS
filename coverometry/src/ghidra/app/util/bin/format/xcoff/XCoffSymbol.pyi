import java.lang


class XCoffSymbol(object):
    N_ABS: int = -1
    N_DEBUG: int = -2
    N_UNDEF: int = 0
    SYMNMLEN: int = 8
    SYMSZ: int = 18



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, optionalHeader: ghidra.app.util.bin.format.xcoff.XCoffOptionalHeader): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isFunction(self) -> bool: ...

    def isLongName(self) -> bool: ...

    def isVariable(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def function(self) -> bool: ...

    @property
    def longName(self) -> bool: ...

    @property
    def name(self) -> unicode: ...

    @property
    def variable(self) -> bool: ...