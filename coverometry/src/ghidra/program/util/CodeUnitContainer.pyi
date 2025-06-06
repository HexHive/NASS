import ghidra.program.model.listing
import java.lang


class CodeUnitContainer(object):




    def __init__(self, codeUnit: ghidra.program.model.listing.CodeUnit): ...



    def equals(self, __a0: object) -> bool: ...

    def getArity(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeUnit(self) -> ghidra.program.model.listing.CodeUnit: ...

    def getMnemonic(self) -> unicode: ...

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

    @property
    def arity(self) -> int: ...

    @property
    def codeUnit(self) -> ghidra.program.model.listing.CodeUnit: ...

    @property
    def mnemonic(self) -> unicode: ...