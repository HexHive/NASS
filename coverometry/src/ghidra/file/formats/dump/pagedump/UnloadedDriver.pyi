import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang


class UnloadedDriver(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    NAME: unicode = u'_DUMP_UNLOADED_DRIVERS'
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

    def getClass(self) -> java.lang.Class: ...

    def getEndAddress(self) -> long: ...

    def getName(self) -> unicode: ...

    def getNameLength(self) -> int: ...

    def getSize(self) -> long: ...

    def getStartAddress(self) -> long: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setEndAddress(self, __a0: long) -> None: ...

    def setName(self, __a0: unicode) -> None: ...

    def setNameLength(self, __a0: int) -> None: ...

    def setStartAddress(self, __a0: long) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def endAddress(self) -> long: ...

    @endAddress.setter
    def endAddress(self, value: long) -> None: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def nameLength(self) -> int: ...

    @nameLength.setter
    def nameLength(self, value: int) -> None: ...

    @property
    def size(self) -> long: ...

    @property
    def startAddress(self) -> long: ...

    @startAddress.setter
    def startAddress(self, value: long) -> None: ...