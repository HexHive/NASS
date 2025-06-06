import ghidra.app.util.bin.format.pdb2.pdbreader
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol
import java.lang


class LocalProcedureMipsIdMsSymbol(ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractProcedureStartMipsMsSymbol):
    PDB_ID: int = 4424



    def __init__(self, __a0: ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb, __a1: ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader): ...



    def emit(self, __a0: java.lang.StringBuilder) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDebugEndOffset(self) -> long: ...

    def getDebugStartOffset(self) -> long: ...

    def getEndPointer(self) -> long: ...

    def getFramePointerRegister(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.RegisterName: ...

    def getName(self) -> unicode: ...

    def getNextPointer(self) -> long: ...

    def getOffset(self) -> long: ...

    def getParentPointer(self) -> long: ...

    def getPdbId(self) -> int: ...

    def getProcedureLength(self) -> long: ...

    def getReturnRegister(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.RegisterName: ...

    def getSegment(self) -> int: ...

    def getTypeRecordNumber(self) -> ghidra.app.util.bin.format.pdb2.pdbreader.RecordNumber: ...

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
    def pdbId(self) -> int: ...