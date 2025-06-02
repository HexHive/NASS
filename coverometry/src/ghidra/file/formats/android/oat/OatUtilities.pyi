from typing import List
import ghidra.app.util.bin
import ghidra.app.util.importer
import ghidra.file.formats.android.dex.format
import ghidra.file.formats.android.oat
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import java.lang


class OatUtilities(object):




    def __init__(self): ...



    @staticmethod
    def adjustForThumbAsNeeded(__a0: ghidra.file.formats.android.oat.OatHeader, __a1: ghidra.program.model.listing.Program, __a2: ghidra.program.model.address.Address, __a3: ghidra.app.util.importer.MessageLog) -> ghidra.program.model.address.Address: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getAllMethods(__a0: ghidra.file.formats.android.dex.format.ClassDataItem) -> List[object]: ...

    @staticmethod
    def getBinaryReader(__a0: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.BinaryReader: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getOatDataSymbol(__a0: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Symbol: ...

    @staticmethod
    def getOatExecSymbol(__a0: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Symbol: ...

    @staticmethod
    def getOatLastWordSymbol(__a0: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Symbol: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isELF(__a0: ghidra.program.model.listing.Program) -> bool: ...

    @staticmethod
    def isOAT(__a0: ghidra.program.model.listing.Program) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

