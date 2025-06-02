import ghidra.app.util.bin
import ghidra.file.formats.dump.mdmp
import ghidra.program.model.data
import java.lang


class TokenListStream(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    NAME: unicode = u'MINIDUMP_TOKEN_LIST'
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

    def getElementHeaderSize(self) -> int: ...

    def getListHeaderSize(self) -> int: ...

    def getToken(self, __a0: int) -> ghidra.file.formats.dump.mdmp.Token: ...

    def getTokenListEntries(self) -> int: ...

    def getTokenListSize(self) -> int: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setElementHeaderSize(self, __a0: int) -> None: ...

    def setListHeaderSize(self, __a0: int) -> None: ...

    def setToken(self, __a0: ghidra.file.formats.dump.mdmp.Token, __a1: int) -> None: ...

    def setTokenListEntries(self, __a0: int) -> None: ...

    def setTokenListSize(self, __a0: int) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def elementHeaderSize(self) -> int: ...

    @elementHeaderSize.setter
    def elementHeaderSize(self, value: int) -> None: ...

    @property
    def listHeaderSize(self) -> int: ...

    @listHeaderSize.setter
    def listHeaderSize(self, value: int) -> None: ...

    @property
    def tokenListEntries(self) -> int: ...

    @tokenListEntries.setter
    def tokenListEntries(self, value: int) -> None: ...

    @property
    def tokenListSize(self) -> int: ...

    @tokenListSize.setter
    def tokenListSize(self, value: int) -> None: ...