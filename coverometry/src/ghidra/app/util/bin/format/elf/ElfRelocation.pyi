import ghidra.app.util.bin
import ghidra.program.model.data
import java.lang


class ElfRelocation(object, ghidra.app.util.bin.StructConverter):
    """
    A class to represent the Elf32_Rel and Elf64_Rel data structure.
 
 
     typedef uint32_t Elf32_Addr;
     typedef uint64_t Elf64_Addr;
     typedef uint32_t Elf32_Word;
     typedef uint64_t Elf64_Xword;
 
     REL entry:
 
        typedef struct {
            Elf32_Addr   r_offset;
            Elf32_Word   r_info;
        } Elf32_Rel;
 
        typedef struct {
            Elf64_Addr   r_offset;
            Elf64_Xword  r_info;
        } Elf64_Rel;
 
     RELA entry with addend:
 
        typedef struct {
            Elf32_Addr    r_offset;
            Elf32_Word    r_info;
            Elf32_Sword   r_addend;
        } Elf32_Rela;
 
        typedef struct {
            Elf64_Addr    r_offset;   //Address
            Elf64_Xword   r_info;     //Relocation type and symbol index
            Elf64_Sxword  r_addend;   //Addend 
        } Elf64_Rela;
 
     RELR entry (see SHT_RELR, DT_RELR):
        NOTE: Relocation type is data relative and must be specified by appropriate relocation handler
        (see ElfRelocationHandler#getRelrRelocationType()) since it is not contained within the 
        relocation table which only specifies r_offset for each entry.
 
 
 
     NOTE: instantiation relies on the use of a default constructor which must be 
     implemented by any extension.  An extension should implement the methods
     #initElfRelocation(BinaryReader, ElfHeader, int, boolean) and/or
     #initElfRelocation(ElfHeader, int, boolean, long, long, long).
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



    def __init__(self):
        """
        Instantiate an uninitialized relocation object.
         <p>
         NOTE: This method is intended for use by the various factory methods which should generally
         be used when building-up a relocation table (see {@link #createElfRelocation(BinaryReader, ElfHeader, int, boolean)}
         and {@link #createElfRelocation(ElfHeader, int, boolean, long, long, long)}).
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getAddend(self) -> long:
        """
        This member specifies the RELA signed-constant addend used to compute 
         the value to be stored into the relocatable field.  This
         value will be 0 for REL entries which do not supply an addend and may
         rely on an implicit addend stored at the relocation offset.
         See {@link #hasAddend()} which is true for RELA / Elf_Rela and false
         for REL / Elf_Rel relocations.
        @return addend as 64-bit signed constant
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getOffset(self) -> long:
        """
        This member gives the location at which to apply the relocation action. 
 
         For a relocatable file, the value is the byte offset from the 
         beginning of the section to the storage unit affected by the relocation. 
 
         For an executable file or a shared object, the value is the virtual address of
         the storage unit affected by the relocation.
        @return the location at which to apply the relocation
        """
        ...

    def getRelocationIndex(self) -> int:
        """
        @return index of relocation within its corresponding relocation table
        """
        ...

    def getRelocationInfo(self) -> long:
        """
        Returns the r_info relocation entry field value
        @return r_info value
        """
        ...

    @staticmethod
    def getStandardRelocationEntrySize(is64bit: bool, hasAddend: bool) -> int:
        """
        Get the standard relocation size when one has notbeen specified
        @param is64bit true if ELF 64-bit
        @param hasAddend true if relocation has addend
        @return size of relocation entry
        """
        ...

    def getSymbolIndex(self) -> int:
        """
        Returns the symbol index where the relocation must be made.
         A value of 0 is generally returned when no symbol is relavent
         to the relocation.
        @return the symbol index
        """
        ...

    def getType(self) -> int:
        """
        The type of relocation to apply.
         NOTE 1: Relocation types are processor-specific (see {@link ElfRelocationHandler}).
         NOTE 2: A type of 0 is returned by default for RELR relocations and must be updated 
         during relocation processing (see {@link #setType(long)}).  The appropriate RELR 
         relocation type can be obtained from the appropriate 
         {@link ElfRelocationHandler#getRelrRelocationType()} or 
         {@link ElfRelocationContext#getRelrRelocationType()} if available.
        @return type of relocation to apply
        """
        ...

    def hasAddend(self) -> bool:
        """
        Returns true if this is a RELA entry with addend
        @return true if this is a RELA entry with addend
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setType(self, type: long) -> None:
        """
        Set the relocation type associated with this relocation.
         Updating the relocation type is required for RELR relocations.
        @param type relocation type to be applied
        """
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addend(self) -> long: ...

    @property
    def offset(self) -> long: ...

    @property
    def relocationIndex(self) -> int: ...

    @property
    def relocationInfo(self) -> long: ...

    @property
    def symbolIndex(self) -> int: ...

    @property
    def type(self) -> int: ...