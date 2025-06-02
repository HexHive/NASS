import ghidra.app.util.bin
import ghidra.app.util.bin.format
import ghidra.app.util.bin.format.elf
import ghidra.program.model.address
import ghidra.program.model.data
import java.io
import java.lang
import java.util.function


class ElfSectionHeader(object, ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.MemoryLoadable):
    """
    A class to represent the Elf32_Shdr data structure.
 
 
     typedef  int32_t  Elf32_Sword;
     typedef uint32_t  Elf32_Word;
     typedef uint32_t  Elf32_Addr;
 
     typedef struct {
         Elf32_Word    sh_name;       //Section name (string tbl index)
         Elf32_Word    sh_type;       //Section type
         Elf32_Word    sh_flags;      //Section flags
         Elf32_Addr    sh_addr;       //Section virtual addr at execution
         Elf32_Off     sh_offset;     //Section file offset
         Elf32_Word    sh_size;       //Section size in bytes
         Elf32_Word    sh_link;       //Link to another section
         Elf32_Word    sh_info;       //Additional section information
         Elf32_Word    sh_addralign;  //Section alignment
         Elf32_Word    sh_entsize;    //Entry size if section holds table *
     } Elf32_Shdr;
 
     typedef  uint32_t  Elf64_Word;
     typedef  uint64_t  Elf64_Xword;
     typedef  uint64_t  Elf64_Addr;
     typedef  uint64_t  Elf64_Off;
 
     typedef struct {
         Elf64_Word    sh_name;       //Section name (string tbl index)
         Elf64_Word    sh_type;       //Section type
         Elf64_Xword   sh_flags;      //Section flags
         Elf64_Addr    sh_addr;       //Section virtual addr at execution
         Elf64_Off     sh_offset;     //Section file offset
         Elf64_Xword   sh_size;       //Section size in bytes
         Elf64_Word    sh_link;       //Link to another section
         Elf64_Word    sh_info;       //Additional section information
         Elf64_Xword   sh_addralign;  //Section alignment
         Elf64_Xword   sh_entsize;    //Entry size if section holds table *
     } Elf64_Shdr;
 
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



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.elf.ElfHeader): ...



    def equals(self, obj: object) -> bool: ...

    def getAddress(self) -> long:
        """
        If the section will appear in the memory image of a process, this 
         member gives the address at which the section's first byte 
         should reside. Otherwise, the member contains 0.
        @return the address of the section in memory
        """
        ...

    def getAddressAlignment(self) -> long:
        """
        Some sections have address alignment constraints. For example, if a section holds a
         doubleword, the system must ensure doubleword alignment for the entire section.
         That is, the value of sh_addr must be congruent to 0, modulo the value of
         sh_addralign. Currently, only 0 and positive integral powers of two are allowed.
         Values 0 and 1 mean the section has no alignment constraints.
        @return the section address alignment constraints
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getElfHeader(self) -> ghidra.app.util.bin.format.elf.ElfHeader:
        """
        Return ElfHeader associated with this section
        @return ElfHeader
        """
        ...

    def getEntrySize(self) -> long:
        """
        Some sections hold a table of fixed-size entries, such as a symbol table. For such a section,
         this member gives the size in bytes of each entry. The member contains 0 if the
         section does not hold a table of fixed-size entries.
        @return the section entry size
        """
        ...

    def getFilteredLoadInputStream(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, start: ghidra.program.model.address.Address, dataLength: long, errorConsumer: java.util.function.BiConsumer) -> java.io.InputStream: ...

    def getFlags(self) -> long:
        """
        Sections support 1-bit flags that describe miscellaneous attributes. Flag definitions
         appear aove.
        @return the section flags
        """
        ...

    def getInfo(self) -> int:
        """
        This member holds extra information, whose interpretation 
         depends on the section type.
  
         If sh_type is SHT_REL or SHT_RELA, then sh_info holds 
         the section header index of the
         section to which the relocation applies.
 
         If sh_type is SHT_SYMTAB or SHT_DYNSYM, then sh_info
         holds one greater than the symbol table index of the last
         local symbol (binding STB_LOCAL).
        @return the section header info
        """
        ...

    def getLink(self) -> int:
        """
        This member holds extra information, whose interpretation 
         depends on the section type.
 
         If sh_type is SHT_SYMTAB, SHT_DYNSYM, or SHT_DYNAMIC, 
         then sh_link holds the section header table index of
         its associated string table.
 
         If sh_type is SHT_REL, SHT_RELA, or SHT_HASH
         sh_link holds the section header index of the 
         associated symbol table.
        @return the section header link
        """
        ...

    def getLogicalSize(self) -> long:
        """
        Returns the logical size of this section, possibly affected by compression.
        @return logical size of this section, see {@link #getSize()}
        """
        ...

    def getName(self) -> int:
        """
        An index into the section header string table section, 
         giving the location of a null-terminated string which is the name of this section.
        @return the index of the section name
        """
        ...

    def getNameAsString(self) -> unicode:
        """
        Returns the actual string name for this section. The section only
         stores an byte index into the string table where
         the name string is located.
        @return the actual string name for this section
        """
        ...

    def getOffset(self) -> long:
        """
        The byte offset from the beginning of the file to the first
         byte in the section.
         One section type, SHT_NOBITS described below, occupies no
         space in the file, and its sh_offset member locates the conceptual placement in the
         file.
        @return byte offset from the beginning of the file to the first byte in the section
        """
        ...

    def getRawInputStream(self) -> java.io.InputStream: ...

    def getReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns the binary reader.
        @return the binary reader
        """
        ...

    def getSize(self) -> long:
        """
        This member gives the section's size in bytes. Unless the section type is
         SHT_NOBITS, the section occupies sh_size bytes in the file. A section of type
         SHT_NOBITS may have a non-zero size, but it occupies no space in the file.
        @return the section's size in bytes
        """
        ...

    def getType(self) -> int:
        """
        This member categorizes the section's contents and semantics.
        @return the section's contents and semantics
        """
        ...

    def getTypeAsString(self) -> unicode:
        """
        Get header type as string.  ElfSectionHeaderType name will be returned
         if know, otherwise a numeric name of the form "SHT_0x12345678" will be returned.
        @return header type as string
        """
        ...

    def hasFilteredLoadInputStream(self, elfLoadHelper: ghidra.app.util.bin.format.elf.ElfLoadHelper, start: ghidra.program.model.address.Address) -> bool: ...

    def hashCode(self) -> int: ...

    def isAlloc(self) -> bool:
        """
        Returns true if this section is allocated (e.g., SHF_ALLOC is set)
        @return true if this section is allocated.
        """
        ...

    def isBytesChanged(self) -> bool:
        """
        Returns true if the data bytes have changed for this section.
        @return true if the data bytes have changed for this section
        """
        ...

    def isCompressed(self) -> bool:
        """
        Returns true if this section is compressed in a supported manner.  This does NOT include
         sections that carry compressed data, such as ".zdebuginfo" type sections.
        @return true if the section was compressed and needs to be decompressed, false if normal
         section
        """
        ...

    def isExecutable(self) -> bool:
        """
        Returns true if this section is executable.
        @return true if this section is executable.
        """
        ...

    def isInvalidOffset(self) -> bool:
        """
        Returns true if this section header's offset is invalid.
        @return true if this section header's offset is invalid
        """
        ...

    def isModified(self) -> bool:
        """
        Returns true if this section has been modified.
         A modified section requires that a new program header
         get created.
        @return true if this section has been modified
        """
        ...

    def isWritable(self) -> bool:
        """
        Returns true if this section is writable.
        @return true if this section is writable.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setAddress(self, addr: long) -> None:
        """
        Sets the start address of this section.
        @param addr the new start address of this section
        """
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        @see ghidra.app.util.bin.StructConverter#toDataType()
        """
        ...

    def toString(self) -> unicode:
        """
        @see java.lang.Object#toString()
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def address(self) -> long: ...

    @address.setter
    def address(self, value: long) -> None: ...

    @property
    def addressAlignment(self) -> long: ...

    @property
    def alloc(self) -> bool: ...

    @property
    def bytesChanged(self) -> bool: ...

    @property
    def compressed(self) -> bool: ...

    @property
    def elfHeader(self) -> ghidra.app.util.bin.format.elf.ElfHeader: ...

    @property
    def entrySize(self) -> long: ...

    @property
    def executable(self) -> bool: ...

    @property
    def flags(self) -> long: ...

    @property
    def info(self) -> int: ...

    @property
    def invalidOffset(self) -> bool: ...

    @property
    def link(self) -> int: ...

    @property
    def logicalSize(self) -> long: ...

    @property
    def modified(self) -> bool: ...

    @property
    def name(self) -> int: ...

    @property
    def nameAsString(self) -> unicode: ...

    @property
    def offset(self) -> long: ...

    @property
    def rawInputStream(self) -> java.io.InputStream: ...

    @property
    def reader(self) -> ghidra.app.util.bin.BinaryReader: ...

    @property
    def size(self) -> long: ...

    @property
    def type(self) -> int: ...

    @property
    def typeAsString(self) -> unicode: ...

    @property
    def writable(self) -> bool: ...