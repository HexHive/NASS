from typing import List
import ghidra.app.util.bin
import ghidra.javaclass.format.attributes
import ghidra.program.model.data
import java.lang


class FieldInfoJava(object, ghidra.app.util.bin.StructConverter):
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



    def __init__(self, __a0: ghidra.app.util.bin.BinaryReader, __a1: ghidra.javaclass.format.ClassFileJava): ...



    def equals(self, __a0: object) -> bool: ...

    def getAccessFlags(self) -> int: ...

    def getAttributes(self) -> List[ghidra.javaclass.format.attributes.AbstractAttributeInfo]: ...

    def getAttributesCount(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getConstantValueAttribute(self) -> ghidra.javaclass.format.attributes.ConstantValueAttribute: ...

    def getDescriptorIndex(self) -> int: ...

    def getNameIndex(self) -> int: ...

    def getOffset(self) -> long: ...

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
    def accessFlags(self) -> int: ...

    @property
    def attributes(self) -> List[ghidra.javaclass.format.attributes.AbstractAttributeInfo]: ...

    @property
    def attributesCount(self) -> int: ...

    @property
    def constantValueAttribute(self) -> ghidra.javaclass.format.attributes.ConstantValueAttribute: ...

    @property
    def descriptorIndex(self) -> int: ...

    @property
    def nameIndex(self) -> int: ...

    @property
    def offset(self) -> long: ...