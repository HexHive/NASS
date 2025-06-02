import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang


class YAFFS2ExtendedTags(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word



    @overload
    def __init__(self): ...

    @overload
    def __init__(self, __a0: List[int]): ...



    def equals(self, __a0: object) -> bool: ...

    def getChunkId(self) -> long: ...

    def getClass(self) -> java.lang.Class: ...

    def getEccColParity(self) -> long: ...

    def getEccLineParity(self) -> long: ...

    def getEccLineParityPrime(self) -> long: ...

    def getNumberBytes(self) -> long: ...

    def getObjectId(self) -> long: ...

    def getSequenceNumber(self) -> long: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def chunkId(self) -> long: ...

    @property
    def eccColParity(self) -> long: ...

    @property
    def eccLineParity(self) -> long: ...

    @property
    def eccLineParityPrime(self) -> long: ...

    @property
    def numberBytes(self) -> long: ...

    @property
    def objectId(self) -> long: ...

    @property
    def sequenceNumber(self) -> long: ...