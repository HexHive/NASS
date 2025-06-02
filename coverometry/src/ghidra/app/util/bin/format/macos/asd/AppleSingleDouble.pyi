from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.macos.asd
import ghidra.program.model.data
import java.lang


class AppleSingleDouble(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DOUBLE_MAGIC_NUMBER: int = 333319
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SINGLE_MAGIC_NUMBER: int = 333312
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word



    def __init__(self, provider: ghidra.app.util.bin.ByteProvider): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getEntryList(self) -> List[ghidra.app.util.bin.format.macos.asd.EntryDescriptor]: ...

    def getFiller(self) -> List[int]: ...

    def getMagicNumber(self) -> int: ...

    def getNumberOfEntries(self) -> int: ...

    def getVersionNumber(self) -> int: ...

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
    def entryList(self) -> List[object]: ...

    @property
    def filler(self) -> List[int]: ...

    @property
    def magicNumber(self) -> int: ...

    @property
    def numberOfEntries(self) -> int: ...

    @property
    def versionNumber(self) -> int: ...