import ghidra.app.util.bin
import ghidra.file.formats.dump.apport
import ghidra.program.model.data
import java.lang


class ApportHeader(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    NAME: unicode = u'APPORT_HEADER'
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word







    def equals(self, __a0: object) -> bool: ...

    def getBlob(self, __a0: int) -> unicode: ...

    def getBlobCount(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getLineCount(self) -> int: ...

    def getMachineImageType(self) -> unicode: ...

    def getMemoryInfo(self, __a0: int) -> ghidra.file.formats.dump.apport.MemoryInfo: ...

    def getMemoryRegionCount(self) -> int: ...

    def getMemoryRegionOffset(self) -> int: ...

    def getSignature(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setSignature(self, __a0: unicode) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def blobCount(self) -> int: ...

    @property
    def lineCount(self) -> int: ...

    @property
    def machineImageType(self) -> unicode: ...

    @property
    def memoryRegionCount(self) -> int: ...

    @property
    def memoryRegionOffset(self) -> int: ...

    @property
    def signature(self) -> unicode: ...

    @signature.setter
    def signature(self, value: unicode) -> None: ...