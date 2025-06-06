import ghidra.app.util.bin.format.pdb2.pdbreader.symbol
import java.lang


class AbstractPublic32MsSymbol(ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractPublicMsSymbol):




    def __init__(self, __a0: ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb, __a1: ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader, __a2: ghidra.app.util.bin.format.pdb2.pdbreader.symbol.PublicSymbolInternals32): ...



    def emit(self, __a0: java.lang.StringBuilder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFlags(self) -> long: ...

    def getName(self) -> unicode: ...

    def getOffset(self) -> long: ...

    def getPdbId(self) -> int: ...

    def getSegment(self) -> int: ...

    def hashCode(self) -> int: ...

    def isCode(self) -> bool: ...

    def isFunction(self) -> bool: ...

    def isManaged(self) -> bool: ...

    def isMicrosoftIntermediateLanguage(self) -> bool: ...

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
    def code(self) -> bool: ...

    @property
    def flags(self) -> long: ...

    @property
    def function(self) -> bool: ...

    @property
    def managed(self) -> bool: ...

    @property
    def microsoftIntermediateLanguage(self) -> bool: ...

    @property
    def name(self) -> unicode: ...

    @property
    def offset(self) -> long: ...

    @property
    def segment(self) -> int: ...