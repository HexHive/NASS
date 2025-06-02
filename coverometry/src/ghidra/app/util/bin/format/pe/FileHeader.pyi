from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe
import ghidra.app.util.bin.format.pe.debug
import ghidra.program.model.data
import ghidra.program.model.mem
import java.lang


class FileHeader(object, ghidra.app.util.bin.StructConverter):
    """
    A class to represent the IMAGE_FILE_HEADER struct as
     defined in winnt.h.
 
 
     typedef struct _IMAGE_FILE_HEADER {
         WORD    Machine;								// MANDATORY
         WORD    NumberOfSections;					// USED
         DWORD   TimeDateStamp;
         DWORD   PointerToSymbolTable;
         DWORD   NumberOfSymbols;
         WORD    SizeOfOptionalHeader;				// USED
         WORD    Characteristics;						// MANDATORY
     } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
 
    """

    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    CHARACTERISTICS: List[unicode] = array(java.lang.String, [u'Relocation info stripped from file', u'File is executable  (i.e. no unresolved externel references)', u'Line nunbers stripped from file', u'Local symbols stripped from file', u'Agressively trim working set', u'App can handle >2gb addresses', u'Bytes of machine word are reversed', u'32 bit word machine', u'Debugging info stripped from file in .DBG file', u'If Image is on removable media, copy and run from the swap file', u'If Image is on Net, copy and run from the swap file', u'System file', u'File is a DLL', u'File should only be run on a UP machine', u'Bytes of machine word are reversed'])
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    IMAGE_FILE_32BIT_MACHINE: int = 256
    IMAGE_FILE_AGGRESIVE_WS_TRIM: int = 16
    IMAGE_FILE_BYTES_REVERSED_HI: int = 32768
    IMAGE_FILE_BYTES_REVERSED_LO: int = 128
    IMAGE_FILE_DEBUG_STRIPPED: int = 512
    IMAGE_FILE_DLL: int = 8192
    IMAGE_FILE_EXECUTABLE_IMAGE: int = 2
    IMAGE_FILE_LARGE_ADDRESS_AWARE: int = 32
    IMAGE_FILE_LINE_NUMS_STRIPPED: int = 4
    IMAGE_FILE_LOCAL_SYMS_STRIPPED: int = 8
    IMAGE_FILE_MACHINE_AM33: int = 467
    IMAGE_FILE_MACHINE_AMD64: int = 34404
    IMAGE_FILE_MACHINE_ARM: int = 448
    IMAGE_FILE_MACHINE_ARM64: int = 43620
    IMAGE_FILE_MACHINE_ARMNT: int = 452
    IMAGE_FILE_MACHINE_EBC: int = 3772
    IMAGE_FILE_MACHINE_I386: int = 332
    IMAGE_FILE_MACHINE_IA64: int = 512
    IMAGE_FILE_MACHINE_M32R: int = 36929
    IMAGE_FILE_MACHINE_MASK: int = 65535
    IMAGE_FILE_MACHINE_MIPS16: int = 614
    IMAGE_FILE_MACHINE_MIPSFPU: int = 870
    IMAGE_FILE_MACHINE_MIPSFPU16: int = 1126
    IMAGE_FILE_MACHINE_POWERPC: int = 496
    IMAGE_FILE_MACHINE_POWERPCFP: int = 497
    IMAGE_FILE_MACHINE_R4000: int = 358
    IMAGE_FILE_MACHINE_RISCV128: int = 20776
    IMAGE_FILE_MACHINE_RISCV32: int = 20530
    IMAGE_FILE_MACHINE_RISCV64: int = 20580
    IMAGE_FILE_MACHINE_SH3: int = 418
    IMAGE_FILE_MACHINE_SH3DSP: int = 419
    IMAGE_FILE_MACHINE_SH4: int = 422
    IMAGE_FILE_MACHINE_SH5: int = 424
    IMAGE_FILE_MACHINE_THUMB: int = 450
    IMAGE_FILE_MACHINE_UNKNOWN: int = 0
    IMAGE_FILE_MACHINE_WCEMIPSV2: int = 361
    IMAGE_FILE_NET_RUN_FROM_SWAP: int = 2048
    IMAGE_FILE_RELOCS_STRIPPED: int = 1
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: int = 1024
    IMAGE_FILE_SYSTEM: int = 4096
    IMAGE_FILE_UP_SYSTEM_ONLY: int = 16384
    IMAGE_SIZEOF_FILE_HEADER: int = 20
    NAME: unicode = u'IMAGE_FILE_HEADER'
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word







    def addSection(self, block: ghidra.program.model.mem.MemoryBlock, optionalHeader: ghidra.app.util.bin.format.pe.OptionalHeader) -> None:
        """
        Adds a new section to this file header. Uses the given memory block
         as the section template. The section will have the memory block's name, start address,
         size, etc. The optional header is needed to determine the free byte position in the
         file.
        @param block the memory block template
        @param optionalHeader the related optional header
        @throws RuntimeException if the memory block is uninitialized
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getCharacteristics(self) -> int:
        """
        Returns a set of bit flags indicating attributes of the file.
        @return a set of bit flags indicating attributes
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getMachine(self) -> int:
        """
        Returns the architecture type of the computer.
        @return the architecture type of the computer
        """
        ...

    def getMachineName(self) -> unicode:
        """
        Returns a string representation of the architecture type of the computer.
        @return a string representation of the architecture type of the computer
        """
        ...

    def getNumberOfSections(self) -> int:
        """
        Returns the number of sections.
         Sections equate to Ghidra memory blocks.
        @return the number of sections
        """
        ...

    def getNumberOfSymbols(self) -> int:
        """
        Returns the number of symbols in the COFF symbol table
        @return the number of symbols in the COFF symbol table
        """
        ...

    def getPointerToSections(self) -> int:
        """
        Returns the file pointer to the section headers.
        @return the file pointer to the section headers
        """
        ...

    def getPointerToSymbolTable(self) -> int:
        """
        Returns the file offset of the COFF symbol table
        @return the file offset of the COFF symbol table
        """
        ...

    @overload
    def getSectionHeader(self, index: int) -> ghidra.app.util.bin.format.pe.SectionHeader:
        """
        Returns the section header at the specified position in the array.
        @param index index of section header to return
        @return the section header at the specified position in the array, or null if invalid
        """
        ...

    @overload
    def getSectionHeader(self, name: unicode) -> ghidra.app.util.bin.format.pe.SectionHeader:
        """
        Get the first section header defined with the specified name
        @param name section name
        @return first section header defined with the specified name or null if not found
        """
        ...

    def getSectionHeaderContaining(self, virtualAddr: int) -> ghidra.app.util.bin.format.pe.SectionHeader:
        """
        Returns the section header that contains the specified virtual address.
        @param virtualAddr the virtual address
        @return the section header that contains the specified virtual address
        """
        ...

    def getSectionHeaders(self) -> List[ghidra.app.util.bin.format.pe.SectionHeader]:
        """
        Returns the array of section headers.
        @return the array of section headers
        """
        ...

    def getSizeOfOptionalHeader(self) -> int:
        """
        Returns the size of the optional header data
        @return the size of the optional header, in bytes
        """
        ...

    def getSymbols(self) -> List[ghidra.app.util.bin.format.pe.debug.DebugCOFFSymbol]:
        """
        Returns the array of symbols.
        @return the array of symbols
        """
        ...

    def getTimeDateStamp(self) -> int:
        """
        Returns the time stamp of the image.
        @return the time stamp of the image
        """
        ...

    def hashCode(self) -> int: ...

    def isLordPE(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        @see ghidra.app.util.bin.StructConverter#toDataType()
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def characteristics(self) -> int: ...

    @property
    def lordPE(self) -> bool: ...

    @property
    def machine(self) -> int: ...

    @property
    def machineName(self) -> unicode: ...

    @property
    def numberOfSections(self) -> int: ...

    @property
    def numberOfSymbols(self) -> int: ...

    @property
    def pointerToSections(self) -> int: ...

    @property
    def pointerToSymbolTable(self) -> int: ...

    @property
    def sectionHeaders(self) -> List[ghidra.app.util.bin.format.pe.SectionHeader]: ...

    @property
    def sizeOfOptionalHeader(self) -> int: ...

    @property
    def symbols(self) -> List[object]: ...

    @property
    def timeDateStamp(self) -> int: ...