import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang


class DyldCacheMappingAndSlideInfo(object, ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_cache_mapping_and_slide_info structure.
    """

    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    DYLD_CACHE_DYNAMIC_CONFIG_DATA: long
    DYLD_CACHE_MAPPING_AUTH_DATA: long
    DYLD_CACHE_MAPPING_CONST_DATA: long
    DYLD_CACHE_MAPPING_DIRTY_DATA: long
    DYLD_CACHE_MAPPING_TEXT_STUBS: long
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



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new {@link DyldCacheImageInfo}.
        @param reader A {@link BinaryReader} positioned at the start of a DYLD mapping info
        @throws IOException if there was an IO-related problem creating the DYLD mapping info
        """
        ...



    def contains(self, addr: long) -> bool:
        """
        Returns true if the mapping contains the given address
        @param addr The address to check
        @return True if the mapping contains the given address; otherwise, false
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> long:
        """
        Gets the address of the start of the mapping.
        @return The address of the start of the mapping
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getFileOffset(self) -> long:
        """
        Gets the file offset of the start of the mapping.
        @return The file offset of the start of the mapping
        """
        ...

    def getFlags(self) -> long:
        """
        Get slide info flags
        @return slide info flags
        """
        ...

    def getSize(self) -> long:
        """
        Gets the size of the mapping.
        @return The size of the mapping
        """
        ...

    def getSlideInfoFileOffset(self) -> long:
        """
        Get slide info file offset
        @return slide info file offset
        """
        ...

    def getSlideInfoFileSize(self) -> long:
        """
        Get slide info file size
        @return slide info file size
        """
        ...

    def hashCode(self) -> int: ...

    def isAuthData(self) -> bool: ...

    def isConfigData(self) -> bool: ...

    def isConstData(self) -> bool: ...

    def isDirtyData(self) -> bool: ...

    def isExecute(self) -> bool:
        """
        Returns true if the initial protections include EXECUTE.
        @return true if the initial protections include EXECUTE
        """
        ...

    def isRead(self) -> bool:
        """
        Returns true if the initial protections include READ.
        @return true if the initial protections include READ
        """
        ...

    def isTextStubs(self) -> bool: ...

    def isWrite(self) -> bool:
        """
        Returns true if the initial protections include WRITE.
        @return true if the initial protections include WRITE
        """
        ...

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
    def address(self) -> long: ...

    @property
    def authData(self) -> bool: ...

    @property
    def configData(self) -> bool: ...

    @property
    def constData(self) -> bool: ...

    @property
    def dirtyData(self) -> bool: ...

    @property
    def execute(self) -> bool: ...

    @property
    def fileOffset(self) -> long: ...

    @property
    def flags(self) -> long: ...

    @property
    def read(self) -> bool: ...

    @property
    def size(self) -> long: ...

    @property
    def slideInfoFileOffset(self) -> long: ...

    @property
    def slideInfoFileSize(self) -> long: ...

    @property
    def textStubs(self) -> bool: ...

    @property
    def write(self) -> bool: ...