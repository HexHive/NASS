from typing import List
import ghidra.app.util.bin.format.pe.debug
import java.lang


class DebugCOFFSymbolTable(object):
    """
    A class to represent the COFF Symbol Table.
    """





    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, coffHeader: ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbolsHeader, offset: int): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getSymbols(self) -> List[ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol]:
        """
        Returns the COFF symbols defined in this COFF symbol table.
        @return the COFF symbols defined in this COFF symbol table
        """
        ...

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
    def symbols(self) -> List[ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol]: ...