import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang


class DyldSubcacheEntry(object, ghidra.app.util.bin.StructConverter):
    """
    Represents a dyld_subcache_entry structure.
    """

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



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Create a new {@link DyldSubcacheEntry}.
        @param reader A {@link BinaryReader} positioned at the start of a DYLD subCache entry
        @throws IOException if there was an IO-related problem creating the DYLD subCache entry
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getCacheExtension(self) -> unicode:
        """
        Gets the extension of this subCache, if it is known
        @return The extension of this subCache, or null if it is not known
        """
        ...

    def getCacheVMOffset(self) -> long:
        """
        Gets the offset of this subCache from the main cache base address
        @return The offset of this subCache from the main cache base address
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getUuid(self) -> unicode:
        """
        Gets the UUID of the subCache file
        @return The UUID of the subCache file
        """
        ...

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
    def cacheExtension(self) -> unicode: ...

    @property
    def cacheVMOffset(self) -> long: ...

    @property
    def uuid(self) -> unicode: ...