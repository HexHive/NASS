import ghidra.app.util.bin.format.pdb2.pdbreader
import java.lang
import java.util


class SymbolRecords(object):




    def __init__(self, __a0: ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb): ...



    @staticmethod
    def deserializeSymbolRecords(__a0: ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb, __a1: ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader) -> java.util.Map: ...

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

