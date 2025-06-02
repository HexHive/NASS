import ghidra.app.util.bin
import ghidra.app.util.bin.format.elf
import java.lang


class ElfSymbol(object):
    """
    A class to represent the ELF 32bit and 64bit Symbol data structures.
 
 
     typedef struct {
         Elf32_Word      st_name;     //Symbol name (string tbl index)
         Elf32_Addr      st_value;    //Symbol value
         Elf32_Word      st_size;     //Symbol size
         unsigned char   st_info;     //Symbol type and binding
         unsigned char   st_other;    //Symbol visibility
         Elf32_Section   st_shndx;    //Section index
     } Elf32_Sym;
 
     typedef struct {
         Elf64_Word       st_name;    //Symbol name (string tbl index)
         unsigned char    st_info;    //Symbol type and binding
         unsigned char    st_other;   //Symbol visibility
         Elf64_Section    st_shndx;   //Section index
         Elf64_Addr       st_value;   //Symbol value
         Elf64_Xword      st_size;    //Symbol size
     } Elf64_Sym;
 
 
    """

    FORMATTED_NO_NAME: unicode = u'<no name>'
    STB_GLOBAL: int = 1
    STB_GNU_UNIQUE: int = 10
    STB_LOCAL: int = 0
    STB_WEAK: int = 2
    STT_COMMON: int = 5
    STT_FILE: int = 4
    STT_FUNC: int = 2
    STT_NOTYPE: int = 0
    STT_OBJECT: int = 1
    STT_RELC: int = 8
    STT_SECTION: int = 3
    STT_SRELC: int = 9
    STT_TLS: int = 6
    STV_DEFAULT: int = 0
    STV_HIDDEN: int = 2
    STV_INTERNAL: int = 1
    STV_PROTECTED: int = 3



    @overload
    def __init__(self):
        """
        Construct a new special null symbol which corresponds to symbol index 0.
        """
        ...

    @overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, symbolIndex: int, symbolTable: ghidra.app.util.bin.format.elf.ElfSymbolTable, header: ghidra.app.util.bin.format.elf.ElfHeader):
        """
        Construct a normal ElfSymbol.
         Warning! the routine initSymbolName() must be called on the symbol later
         to initialize the string name.  This is a performance enhancement.
        @param reader to read symbol from
        @param symbolIndex index of the symbol to read
        @param symbolTable symbol table to associate the symbol to
        @param header else header
        @throws IOException if an issue with reading occurs
        """
        ...



    def equals(self, obj: object) -> bool: ...

    def getBind(self) -> int:
        """
        Returns the symbol's binding. For example, global.
        @return the symbol's binding
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getExtendedSectionHeaderIndex(self) -> int:
        """
        Get the extended symbol section index value when <code>st_shndx</code>
         ({@link #getSectionHeaderIndex()}) has a value of SHN_XINDEX.  This requires a lookup
         into a table defined by an associated SHT_SYMTAB_SHNDX section.
        @return extended symbol section index value
        """
        ...

    def getFormattedName(self) -> unicode:
        """
        Returns the formatted string name for this symbol. If the name is blank or
         can not be resolved due to a missing string table the literal string 
         <I>&lt;no name&gt;</I> will be returned.
         the name string is located.
        @return the actual string name for this symbol or the literal string <I>&lt;no name&gt;</I>
        """
        ...

    def getInfo(self) -> int:
        """
        This member specifies the symbol's type and binding attributes.
        @return the symbol's type and binding attributes
        """
        ...

    def getName(self) -> int:
        """
        This member holds an index into the object file's symbol 
         string table, which holds the character representations 
         of the symbol names. If the value is non-zero, it represents a
         string table index that gives the symbol name.
         Otherwise, the symbol table entry has no name.
        @return the index to the symbol's name
        """
        ...

    def getNameAsString(self) -> unicode:
        """
        Returns the actual string name for this symbol. The symbol only
         stores an byte index into the string table where
         the name string is located.
        @return the actual string name for this symbol (may be null or empty string)
        """
        ...

    def getOther(self) -> int:
        """
        This member currently holds 0 and has no defined meaning.
        @return no defined meaning
        """
        ...

    def getSectionHeaderIndex(self) -> int:
        """
        Get the raw section index value (<code>st_shndx</code>) for this symbol.
         Special values (SHN_LORESERVE and higher) must be treated properly.  The value SHN_XINDEX 
         indicates that the extended value must be used to obtained the actual section index 
         (see {@link #getExtendedSectionHeaderIndex()}).
        @return the <code>st_shndx</code> section index value
        """
        ...

    def getSize(self) -> long:
        """
        Many symbols have associated sizes. For example, a data object's size is the number of
         bytes contained in the object. This member holds 0 if the symbol has no size or an
         unknown size.
        @return the symbol's size
        """
        ...

    def getSymbolTable(self) -> ghidra.app.util.bin.format.elf.ElfSymbolTable:
        """
        Get the symbol table containing this symbol
        @return symbol table
        """
        ...

    def getSymbolTableIndex(self) -> int:
        """
        Get the index of this symbol within the corresponding symbol table.
        @return index of this symbol within the corresponding symbol table
        """
        ...

    def getType(self) -> int:
        """
        Returns the symbol's binding. For example, section.
        @return the symbol's binding
        """
        ...

    def getValue(self) -> long:
        """
        This member gives the value of the associated symbol.
         Depending on the context, this may be an absolute value, 
         an address, etc.
        @return the symbol's value
        """
        ...

    def getVisibility(self) -> int:
        """
        Returns the symbol's visibility. For example, default.
        @return the symbol's visibility
        """
        ...

    def hasProcessorSpecificSymbolSectionIndex(self) -> bool:
        """
        Determine if st_shndx is within the reserved processor-specific index range
        @return true if specified symbol section index corresponds to a processor
         specific value in the range SHN_LOPROC..SHN_HIPROC, else false
        """
        ...

    def hashCode(self) -> int: ...

    def initSymbolName(self, reader: ghidra.app.util.bin.BinaryReader, stringTable: ghidra.app.util.bin.format.elf.ElfStringTable) -> None:
        """
        Initialize the string name of the symbol.
 
         NOTE: This routine MUST be called for each
         ELFSymbol after the elf symbols have been created.
 
         This is done separately from the initial symbol entry read because
         the string names are in a separate location.  If they are read
         at the same time the reading buffer will jump around and significantly
         degrade reading performance.
        @param reader to read from
        @param stringTable stringTable to initialize symbol name
        """
        ...

    def isAbsolute(self) -> bool:
        """
        Returns true if the symbol has an absolute 
         value that will not change because of relocation.
        @return true if the symbol value will not change due to relocation
        """
        ...

    def isCommon(self) -> bool:
        """
        The symbol labels a common block that has not yet been allocated. The symbol's value
         gives alignment constraints, similar to a section's sh_addralign member. That is, the
         link editor will allocate the storage for the symbol at an address that is a multiple of
         st_value. The symbol's size tells how many bytes are required.
        @return true if this is a common symbol
        """
        ...

    def isExternal(self) -> bool:
        """
        Returns true if this is an external symbol.
         A symbol is considered external if it's 
         binding is global and it's size is zero.
        @return true if this is an external symbol
        """
        ...

    def isFile(self) -> bool:
        """
        Returns true if this symbol defines a file.
        @return true if this symbol defines a file
        """
        ...

    def isFunction(self) -> bool:
        """
        Returns true if this symbol defines a function.
        @return true if this symbol defines a function
        """
        ...

    def isGlobal(self) -> bool:
        """
        Returns true if this symbol is global.
         Global symbols are visible to all object files 
         being combined. One object file's definition
         of a global symbol will satisfy another
         file's undefined reference to the same
         global symbol.
        @return true if this symbol is global
        """
        ...

    def isLocal(self) -> bool:
        """
        Returns true if this symbol is local.
         Local symbols are not visible outside the object file
         containing their definition. Local symbols of the same
         name may exist in multiple files without colliding.
        @return true if this symbol is local
        """
        ...

    def isNoType(self) -> bool:
        """
        Returns true if this symbol's type is not specified.
        @return true if this symbol's type is not specified
        """
        ...

    def isObject(self) -> bool:
        """
        Returns true if this symbol defines an object.
        @return true if this symbol defines an object
        """
        ...

    def isSection(self) -> bool:
        """
        Returns true if this symbol defines a section.
        @return true if this symbol defines a section
        """
        ...

    def isTLS(self) -> bool:
        """
        Returns true if this symbol defines a thread-local symbol.
        @return true if this symbol defines a thread-local symbol
        """
        ...

    def isWeak(self) -> bool:
        """
        Returns true if this symbol is weak.
         Weak symbols resemble global symbols,
         but their definitions have lower precedence.
        @return true if this symbol is weak
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

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
    def TLS(self) -> bool: ...

    @property
    def absolute(self) -> bool: ...

    @property
    def bind(self) -> int: ...

    @property
    def common(self) -> bool: ...

    @property
    def extendedSectionHeaderIndex(self) -> int: ...

    @property
    def external(self) -> bool: ...

    @property
    def file(self) -> bool: ...

    @property
    def formattedName(self) -> unicode: ...

    @property
    def function(self) -> bool: ...

    @property
    def global(self) -> bool: ...

    @property
    def info(self) -> int: ...

    @property
    def local(self) -> bool: ...

    @property
    def name(self) -> int: ...

    @property
    def nameAsString(self) -> unicode: ...

    @property
    def noType(self) -> bool: ...

    @property
    def object(self) -> bool: ...

    @property
    def other(self) -> int: ...

    @property
    def section(self) -> bool: ...

    @property
    def sectionHeaderIndex(self) -> int: ...

    @property
    def size(self) -> long: ...

    @property
    def symbolTable(self) -> ghidra.app.util.bin.format.elf.ElfSymbolTable: ...

    @property
    def symbolTableIndex(self) -> int: ...

    @property
    def type(self) -> int: ...

    @property
    def value(self) -> long: ...

    @property
    def visibility(self) -> int: ...

    @property
    def weak(self) -> bool: ...