from typing import List
import ghidra.app.util.bin.format.elf
import ghidra.program.model.data
import java.lang


class ElfSymbolTable(object, ghidra.app.util.bin.format.elf.ElfFileSection):
    """
    A container class to hold ELF symbols.
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



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.elf.ElfHeader, symbolTableSection: ghidra.app.util.bin.format.elf.ElfSectionHeader, fileOffset: long, addrOffset: long, length: long, entrySize: long, stringTable: ghidra.app.util.bin.format.elf.ElfStringTable, symbolSectionIndexTable: List[int], isDynamic: bool):
        """
        Construct and parse an Elf symbol table
        @param reader byte reader
        @param header elf header
        @param symbolTableSection string table section header or null if associated with a dynamic table entry
        @param fileOffset symbol table file offset
        @param addrOffset memory address of symbol table (should already be adjusted for prelink)
        @param length length of symbol table in bytes of -1 if unknown
        @param entrySize size of each symbol entry in bytes
        @param stringTable associated string table
        @param symbolSectionIndexTable extended symbol section index table (may be null, used when 
                   symbol <code>st_shndx == SHN_XINDEX</code>).  See 
                   {@link ElfSymbol#getExtendedSectionHeaderIndex()}).
        @param isDynamic true if symbol table is the dynamic symbol table
        @throws IOException if an IO or parse error occurs
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getAddressOffset(self) -> long: ...

    def getClass(self) -> java.lang.Class: ...

    def getEntrySize(self) -> int: ...

    def getExtendedSectionIndex(self, sym: ghidra.app.util.bin.format.elf.ElfSymbol) -> int:
        """
        Get the extended symbol section index value for the specified ELF symbol which originated
         from this symbol table.   This section index is provided by an associated SHT_SYMTAB_SHNDX 
         section when the symbols st_shndx == SHN_XINDEX.
        @param sym ELF symbol from this symbol table
        @return associated extended section index value or 0 if not defined.
        """
        ...

    def getFileOffset(self) -> long: ...

    def getFormattedSymbolName(self, symbolIndex: int) -> unicode:
        """
        Get the formatted ELF symbol name which corresponds to the specified index. 
         If the name is blank or can not be resolved due to a missing string table the 
         literal string <I>&lt;no name&gt;</I> will be returned.
        @param symbolIndex symbol index
        @return formatted symbol name which corresponds to symbol index or the 
         literal string <I>&lt;no name&gt;</I>
        """
        ...

    def getGlobalSymbols(self) -> List[ghidra.app.util.bin.format.elf.ElfSymbol]:
        """
        Returns all of the global symbols.
        @return all of the global symbols
        """
        ...

    def getLength(self) -> long: ...

    def getSourceFiles(self) -> List[unicode]:
        """
        Returns all of the sources file names.
        @return all of the sources file names
        """
        ...

    def getStringTable(self) -> ghidra.app.util.bin.format.elf.ElfStringTable:
        """
        Returns the associated string table section.
        @return the associated string table section
        """
        ...

    def getSymbol(self, symbolIndex: int) -> ghidra.app.util.bin.format.elf.ElfSymbol:
        """
        Get the Elf symbol which corresponds to the specified index.  Each relocation table
         may correspond to a specific symbol table to which the specified symbolIndex will be
         applied.
        @param symbolIndex symbol index
        @return Elf symbol which corresponds to symbol index or <B>null</B> if out of range
        """
        ...

    def getSymbolAt(self, addr: long) -> ghidra.app.util.bin.format.elf.ElfSymbol:
        """
        Returns the symbol at the specified address.
        @param addr the symbol address
        @return the symbol at the specified address
        """
        ...

    def getSymbolCount(self) -> int:
        """
        @return number of symbols
        """
        ...

    def getSymbolIndex(self, symbol: ghidra.app.util.bin.format.elf.ElfSymbol) -> int:
        """
        Returns the index of the specified symbol in this
         symbol table.
        @param symbol the symbol
        @return the index of the specified symbol
        """
        ...

    def getSymbolName(self, symbolIndex: int) -> unicode:
        """
        Get the ELF symbol name which corresponds to the specified index.
        @param symbolIndex symbol index
        @return symbol name which corresponds to symbol index or null if out of range
        """
        ...

    def getSymbols(self) -> List[ghidra.app.util.bin.format.elf.ElfSymbol]:
        """
        Returns all of the symbols defined in this symbol table.
        @return all of the symbols defined in this symbol table
        """
        ...

    def getTableSectionHeader(self) -> ghidra.app.util.bin.format.elf.ElfSectionHeader:
        """
        Get the section header which corresponds to this table, or null
         if only associated with a dynamic table entry
        @return symbol table section header or null
        """
        ...

    def hashCode(self) -> int: ...

    def isDynamic(self) -> bool:
        """
        Returns true if this is the dynamic symbol table
        @return true if this is the dynamic symbol table
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
    def addressOffset(self) -> long: ...

    @property
    def dynamic(self) -> bool: ...

    @property
    def entrySize(self) -> int: ...

    @property
    def fileOffset(self) -> long: ...

    @property
    def globalSymbols(self) -> List[ghidra.app.util.bin.format.elf.ElfSymbol]: ...

    @property
    def length(self) -> long: ...

    @property
    def sourceFiles(self) -> List[unicode]: ...

    @property
    def stringTable(self) -> ghidra.app.util.bin.format.elf.ElfStringTable: ...

    @property
    def symbolCount(self) -> int: ...

    @property
    def symbols(self) -> List[ghidra.app.util.bin.format.elf.ElfSymbol]: ...

    @property
    def tableSectionHeader(self) -> ghidra.app.util.bin.format.elf.ElfSectionHeader: ...