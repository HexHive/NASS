import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang


class UnloadedModule(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    NAME: unicode = u'MINIDUMP_UNLOADED_MODULE'
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

    def getBaseOfImage(self) -> long: ...

    def getCheckSum(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getModuleNameRVA(self) -> int: ...

    def getSizeOfImage(self) -> long: ...

    def getTimeDateStamp(self) -> int: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setBaseOfImage(self, __a0: long) -> None: ...

    def setCheckSum(self, __a0: int) -> None: ...

    def setModuleNameRVA(self, __a0: int) -> None: ...

    def setSizeOfImage(self, __a0: long) -> None: ...

    def setTimeDateStamp(self, __a0: int) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def baseOfImage(self) -> long: ...

    @baseOfImage.setter
    def baseOfImage(self, value: long) -> None: ...

    @property
    def checkSum(self) -> int: ...

    @checkSum.setter
    def checkSum(self, value: int) -> None: ...

    @property
    def moduleNameRVA(self) -> int: ...

    @moduleNameRVA.setter
    def moduleNameRVA(self, value: int) -> None: ...

    @property
    def sizeOfImage(self) -> long: ...

    @sizeOfImage.setter
    def sizeOfImage(self, value: long) -> None: ...

    @property
    def timeDateStamp(self) -> int: ...

    @timeDateStamp.setter
    def timeDateStamp(self, value: int) -> None: ...