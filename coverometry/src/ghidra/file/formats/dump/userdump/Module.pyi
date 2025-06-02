import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang


class Module(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    NAME: unicode = u'MODULE_'
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

    def getModuleBase(self) -> long: ...

    def getModuleName(self) -> unicode: ...

    def getModuleNameLength(self) -> int: ...

    def getModuleSize(self) -> long: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setModuleBase(self, __a0: long) -> None: ...

    def setModuleName(self, __a0: unicode) -> None: ...

    def setModuleNameLength(self, __a0: int) -> None: ...

    def setModuleSize(self, __a0: long) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def moduleBase(self) -> long: ...

    @moduleBase.setter
    def moduleBase(self, value: long) -> None: ...

    @property
    def moduleName(self) -> unicode: ...

    @moduleName.setter
    def moduleName(self, value: unicode) -> None: ...

    @property
    def moduleNameLength(self) -> int: ...

    @moduleNameLength.setter
    def moduleNameLength(self, value: int) -> None: ...

    @property
    def moduleSize(self) -> long: ...

    @moduleSize.setter
    def moduleSize(self, value: long) -> None: ...