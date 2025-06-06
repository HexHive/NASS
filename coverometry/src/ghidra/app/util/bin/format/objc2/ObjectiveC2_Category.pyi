import ghidra.app.util.bin
import ghidra.app.util.bin.format.objc2
import ghidra.program.model.data
import java.lang


class ObjectiveC2_Category(object, ghidra.app.util.bin.StructConverter):
    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    NAME: unicode = u'category_t'
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

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getClassMethods(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_MethodList: ...

    def getCls(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_Class: ...

    def getIndex(self) -> long: ...

    def getInstanceMethods(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_MethodList: ...

    def getInstanceProperties(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_PropertyList: ...

    def getName(self) -> unicode: ...

    def getProtocols(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_ProtocolList: ...

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
    def classMethods(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_MethodList: ...

    @property
    def cls(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_Class: ...

    @property
    def index(self) -> long: ...

    @property
    def instanceMethods(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_MethodList: ...

    @property
    def instanceProperties(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_PropertyList: ...

    @property
    def name(self) -> unicode: ...

    @property
    def protocols(self) -> ghidra.app.util.bin.format.objc2.ObjectiveC2_ProtocolList: ...