import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang


class PefDebug(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SIZEOF: int = 18
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word



    def __init__(self, memory: ghidra.program.model.mem.Memory, address: ghidra.program.model.address.Address): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDistance(self) -> int: ...

    def getFlags(self) -> int: ...

    def getName(self) -> unicode: ...

    def getNameLength(self) -> int: ...

    def getType(self) -> int: ...

    def getUnknown(self) -> int: ...

    def hashCode(self) -> int: ...

    def isValid(self) -> bool: ...

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
    def distance(self) -> int: ...

    @property
    def flags(self) -> int: ...

    @property
    def name(self) -> unicode: ...

    @property
    def nameLength(self) -> int: ...

    @property
    def type(self) -> int: ...

    @property
    def unknown(self) -> int: ...

    @property
    def valid(self) -> bool: ...