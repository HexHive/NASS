import ghidra.app.util.bin
import ghidra.app.util.bin.format.objc2
import ghidra.program.model.data
import java.lang


class ObjectiveC2_Class(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    NAME: unicode = u'class_t'
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word



    def __init__(self, state: ghidra.app.util.bin.format.objc2.ObjectiveC2_State, reader: ghidra.app.util.bin.BinaryReader): ...



    def applyTo(self) -> None: ...

    def equals(self, that: object) -> bool: ...

    def getCache(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_Cache: ...

    def getClass(self) -> java.lang.Class: ...

    def getData(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_ClassRW: ...

    def getISA(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_Class: ...

    def getIndex(self) -> long: ...

    def getSuperClass(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_Class: ...

    def getVTable(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_Implementation: ...

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
    def ISA(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_Class: ...

    @property
    def VTable(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_Implementation: ...

    @property
    def cache(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_Cache: ...

    @property
    def data(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_ClassRW: ...

    @property
    def index(self) -> long: ...

    @property
    def superClass(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_Class: ...