from typing import List
import ghidra.app.util.bin
import ghidra.file.formats.ext4
import ghidra.program.model.data
import java.lang


class Ext4DirEntry(object, ghidra.app.util.bin.StructConverter):
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







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getExtra(self) -> List[int]: ...

    def getInode(self) -> int: ...

    def getName(self) -> unicode: ...

    def getName_len(self) -> int: ...

    def getRec_len(self) -> int: ...

    def hashCode(self) -> int: ...

    def isUnused(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def read(__a0: ghidra.app.util.bin.BinaryReader) -> ghidra.file.formats.ext4.Ext4DirEntry: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def extra(self) -> List[int]: ...

    @property
    def inode(self) -> int: ...

    @property
    def name(self) -> unicode: ...

    @property
    def name_len(self) -> int: ...

    @property
    def rec_len(self) -> int: ...

    @property
    def unused(self) -> bool: ...