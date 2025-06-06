from typing import List
import ghidra.app.util.bin.format.pdb2.pdbreader
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol
import java.lang


class EnregisteredFieldOfSymbolDARMsSymbol(ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractDefinedSingleAddressRangeMsSymbol):
    PDB_ID: int = 4419



    def __init__(self, __a0: ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb, __a1: ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader): ...



    def emit(self, __a0: java.lang.StringBuilder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddressGapList(self) -> List[object]: ...

    def getAddressRange(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AddressRange: ...

    def getClass(self) -> java.lang.Class: ...

    def getOffsetInParent(self) -> int: ...

    def getPdbId(self) -> int: ...

    def getRangeAttribute(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.symbol.RangeAttribute: ...

    def getRegister(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.RegisterName: ...

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
    def offsetInParent(self) -> int: ...

    @property
    def pdbId(self) -> int: ...

    @property
    def rangeAttribute(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.symbol.RangeAttribute: ...

    @property
    def register(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.RegisterName: ...