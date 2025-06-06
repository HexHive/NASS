from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.macos.rm
import ghidra.program.model.data
import java.lang


class ResourceMap(object, ghidra.app.util.bin.StructConverter):
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

    def getCopy(self) -> ghidra.app.util.bin.format.macos.rm.ResourceHeader: ...

    def getFileReferenceNumber(self) -> int: ...

    def getHandleToNextResourceMap(self) -> int: ...

    def getMapStartIndex(self) -> long: ...

    def getNumberOfTypes(self) -> int: ...

    def getReferenceEntryList(self) -> List[ghidra.app.util.bin.format.macos.rm.ReferenceListEntry]: ...

    def getResourceForkAttributes(self) -> int: ...

    def getResourceNameListOffset(self) -> int: ...

    def getResourceTypeList(self) -> List[ghidra.app.util.bin.format.macos.rm.ResourceType]: ...

    def getResourceTypeListOffset(self) -> int: ...

    def getStringAt(self, offset: int) -> unicode: ...

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
    def copy(self) -> ghidra.app.util.bin.format.macos.rm.ResourceHeader: ...

    @property
    def fileReferenceNumber(self) -> int: ...

    @property
    def handleToNextResourceMap(self) -> int: ...

    @property
    def mapStartIndex(self) -> long: ...

    @property
    def numberOfTypes(self) -> int: ...

    @property
    def referenceEntryList(self) -> List[object]: ...

    @property
    def resourceForkAttributes(self) -> int: ...

    @property
    def resourceNameListOffset(self) -> int: ...

    @property
    def resourceTypeList(self) -> List[object]: ...

    @property
    def resourceTypeListOffset(self) -> int: ...