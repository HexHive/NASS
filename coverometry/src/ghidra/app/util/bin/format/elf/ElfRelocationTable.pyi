from typing import List
import ghidra.app.util.bin.format.elf
import ghidra.program.model.data
import java.lang
import java.util


class ElfRelocationTable(object, ghidra.app.util.bin.format.elf.ElfFileSection):
    """
    A container class to hold ELF relocations.
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




    class TableFormat(java.lang.Enum):
        ANDROID: ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat = ANDROID
        DEFAULT: ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat = DEFAULT
        RELR: ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat = RELR







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.elf.ElfHeader, relocTableSection: ghidra.app.util.bin.format.elf.ElfSectionHeader, fileOffset: long, addrOffset: long, length: long, entrySize: long, addendTypeReloc: bool, symbolTable: ghidra.app.util.bin.format.elf.ElfSymbolTable, sectionToBeRelocated: ghidra.app.util.bin.format.elf.ElfSectionHeader, format: ghidra.app.util.bin.format.elf.ElfRelocationTable.TableFormat):
        """
        Construct an Elf Relocation Table
        @param reader byte provider reader
        @param header elf header
        @param relocTableSection relocation table section header or null if associated with a dynamic table entry
        @param fileOffset relocation table file offset
        @param addrOffset memory address of relocation table (should already be adjusted for prelink)
        @param length length of relocation table in bytes
        @param entrySize size of each relocation entry in bytes
        @param addendTypeReloc true if addend type relocation table
        @param symbolTable associated symbol table (may be null if not applicable)
        @param sectionToBeRelocated or null for dynamic relocation table
        @param format table format
        @throws IOException if an IO or parse error occurs
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getAddressOffset(self) -> long: ...

    def getAssociatedSymbolTable(self) -> ghidra.app.util.bin.format.elf.ElfSymbolTable:
        """
        Returns the associated symbol table.
         A relocation object contains a symbol index.
         This index is into this symbol table.
        @return the associated symbol table or null if not applicable to this reloc table
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getEntrySize(self) -> int: ...

    def getFileOffset(self) -> long: ...

    def getLength(self) -> long: ...

    def getRelocationCount(self) -> int:
        """
        Get number of relocation entries contained within this table
        @return relocation entry count
        """
        ...

    def getRelocations(self) -> List[ghidra.app.util.bin.format.elf.ElfRelocation]:
        """
        Returns the relocations defined in this table.
        @return the relocations defined in this table
        """
        ...

    def getSectionToBeRelocated(self) -> ghidra.app.util.bin.format.elf.ElfSectionHeader:
        """
        Returns the section where the relocations will be applied.
         For example, this method will return ".plt" for ".rel.plt"
        @return the section where the relocations will be applied
         or null for dynamic relocation table not associated with 
         a section.
        """
        ...

    def getTableSectionHeader(self) -> ghidra.app.util.bin.format.elf.ElfSectionHeader:
        """
        Get section header which corresponds to this table, or null
         if only associated with a dynamic table entry
        @return relocation table section header or null
        """
        ...

    def hasAddendRelocations(self) -> bool:
        """
        @return true if has addend relocations, otherwise addend extraction from
         relocation target may be required
        """
        ...

    def hashCode(self) -> int: ...

    def isMissingRequiredSymbolTable(self) -> bool:
        """
        Determine if required symbol table is missing.  If so, relocations may not be processed.
        @return true if required symbol table is missing, else false
        """
        ...

    def isRelrTable(self) -> bool: ...

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
    def addressOffset(self) -> long: ...

    @property
    def associatedSymbolTable(self) -> ghidra.app.util.bin.format.elf.ElfSymbolTable: ...

    @property
    def entrySize(self) -> int: ...

    @property
    def fileOffset(self) -> long: ...

    @property
    def length(self) -> long: ...

    @property
    def missingRequiredSymbolTable(self) -> bool: ...

    @property
    def relocationCount(self) -> int: ...

    @property
    def relocations(self) -> List[ghidra.app.util.bin.format.elf.ElfRelocation]: ...

    @property
    def relrTable(self) -> bool: ...

    @property
    def sectionToBeRelocated(self) -> ghidra.app.util.bin.format.elf.ElfSectionHeader: ...

    @property
    def tableSectionHeader(self) -> ghidra.app.util.bin.format.elf.ElfSectionHeader: ...