from typing import List
import ghidra.app.util.bin.format.swift
import ghidra.app.util.bin.format.swift.types
import ghidra.program.model.data
import java.lang


class CaptureDescriptor(object, ghidra.app.util.bin.format.swift.SwiftStructure):
    """
    Represents a Swift CaptureDescriptor structure
    """

    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DATA_TYPE_CATEGORY: unicode = u'/Swift'
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SIZE: int = 12
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates a new {@link CaptureDescriptor}
        @param reader A {@link BinaryReader} positioned at the start of the structure
        @throws IOException if there was an IO-related problem creating the structure
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getCaptureTypeRecords(self) -> List[ghidra.app.util.bin.format.swift.types.CaptureTypeRecord]:
        """
        Gets the {@link List} of {@link CaptureTypeRecord}s
        @return The {@link List} of {@link CaptureTypeRecord}s
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getMetadataSourceRecords(self) -> List[ghidra.app.util.bin.format.swift.types.MetadataSourceRecord]:
        """
        Gets the {@link List} of {@link MetadataSourceRecord}s
        @return The {@link List} of {@link MetadataSourceRecord}s
        """
        ...

    def getNumBindings(self) -> int:
        """
        Gets the number of bindings
        @return The number of bindings
        """
        ...

    def getNumCaptureTypes(self) -> int:
        """
        Gets the number of capture types
        @return The number of capture types
        """
        ...

    def getNumMetadataSources(self) -> int:
        """
        Gets the number of metadata sources
        @return The number of metadata sources
        """
        ...

    def getStructureName(self) -> unicode: ...

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
    def captureTypeRecords(self) -> List[object]: ...

    @property
    def description(self) -> unicode: ...

    @property
    def metadataSourceRecords(self) -> List[object]: ...

    @property
    def numBindings(self) -> int: ...

    @property
    def numCaptureTypes(self) -> int: ...

    @property
    def numMetadataSources(self) -> int: ...

    @property
    def structureName(self) -> unicode: ...