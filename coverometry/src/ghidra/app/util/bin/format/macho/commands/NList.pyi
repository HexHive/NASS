from typing import List
import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang


class NList(object, ghidra.app.util.bin.StructConverter):
    """
    Represents an nlist and nlist_64 structure.
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



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, is32bit: bool): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> int:
        """
        A 16-bit value providing additional information about this symbol.
        @return a 16-bit value providing additional information about this symbol
        """
        ...

    def getLibraryOrdinal(self) -> int: ...

    def getSection(self) -> int:
        """
        An integer specifying the number of the section that this
         symbol can be found in, or NO_SECT if
         symbol is not found in a section of this image.
        @return the number of the section
        """
        ...

    @overload
    def getSize(self) -> int: ...

    @overload
    @staticmethod
    def getSize(__a0: List[object]) -> int: ...

    def getString(self) -> unicode:
        """
        Returns the symbol string defined at the symbol table command
         string table offset plus n_strx.
        @return the symbol string
        """
        ...

    def getStringTableIndex(self) -> int:
        """
        Returns the index into the string table.
        @return the index into the string table
        """
        ...

    def getType(self) -> int:
        """
        Returns the symbol type flag.
        @return the symbol type flag
        """
        ...

    def getValue(self) -> long:
        """
        An integer that contains the value of this symbol.
         The format of this value is different for each type of symbol.
        @return the value of this symbol
        """
        ...

    def hashCode(self) -> int: ...

    def initString(self, reader: ghidra.app.util.bin.BinaryReader, stringTableOffset: long) -> None:
        """
        Initialize the string from the string table.
         <p>
         You MUST call this method after the NLIST element is created!
         <p>
         Reading a large NList table can cause a large performance issue if the strings
         are initialized as the NList entry is created.  The string table indexes are
         scattered.  Initializing the strings linearly from the string table is much
         faster.
        @param reader The BinaryReader
        @param stringTableOffset offset of the string table
        """
        ...

    def is32bit(self) -> bool: ...

    def isExternal(self) -> bool: ...

    def isIndirect(self) -> bool: ...

    def isLazyBind(self) -> bool: ...

    def isPrivateExternal(self) -> bool: ...

    def isSymbolicDebugging(self) -> bool: ...

    def isThumbSymbol(self) -> bool: ...

    def isTypeAbsolute(self) -> bool: ...

    def isTypePreboundUndefined(self) -> bool: ...

    def isTypeUndefined(self) -> bool: ...

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
    def 32bit(self) -> bool: ...

    @property
    def description(self) -> int: ...

    @property
    def external(self) -> bool: ...

    @property
    def indirect(self) -> bool: ...

    @property
    def lazyBind(self) -> bool: ...

    @property
    def libraryOrdinal(self) -> int: ...

    @property
    def privateExternal(self) -> bool: ...

    @property
    def section(self) -> int: ...

    @property
    def size(self) -> int: ...

    @property
    def string(self) -> unicode: ...

    @property
    def stringTableIndex(self) -> int: ...

    @property
    def symbolicDebugging(self) -> bool: ...

    @property
    def thumbSymbol(self) -> bool: ...

    @property
    def type(self) -> int: ...

    @property
    def typeAbsolute(self) -> bool: ...

    @property
    def typePreboundUndefined(self) -> bool: ...

    @property
    def typeUndefined(self) -> bool: ...

    @property
    def value(self) -> long: ...