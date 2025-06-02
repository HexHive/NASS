from typing import List
import ghidra.app.util.bin
import ghidra.file.formats.android.dex.format
import ghidra.program.model.data
import java.lang


class AnnotationsDirectoryItem(object, ghidra.app.util.bin.StructConverter):
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



    def __init__(self, __a0: ghidra.app.util.bin.BinaryReader, __a1: ghidra.file.formats.android.dex.format.DexHeader): ...



    def equals(self, __a0: object) -> bool: ...

    def getAnnotatedMethodsSize(self) -> int: ...

    def getAnnotatedParametersSize(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getClassAnnotations(self) -> ghidra.file.formats.android.dex.format.AnnotationSetItem: ...

    def getClassAnnotationsOffset(self) -> int: ...

    def getFieldAnnotations(self) -> List[object]: ...

    def getFieldsSize(self) -> int: ...

    def getMethodAnnotations(self) -> List[object]: ...

    def getParameterAnnotations(self) -> List[object]: ...

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
    def annotatedMethodsSize(self) -> int: ...

    @property
    def annotatedParametersSize(self) -> int: ...

    @property
    def classAnnotations(self) -> ghidra.file.formats.android.dex.format.AnnotationSetItem: ...

    @property
    def classAnnotationsOffset(self) -> int: ...

    @property
    def fieldAnnotations(self) -> List[object]: ...

    @property
    def fieldsSize(self) -> int: ...

    @property
    def methodAnnotations(self) -> List[object]: ...

    @property
    def parameterAnnotations(self) -> List[object]: ...