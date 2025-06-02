import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe
import ghidra.program.model.data
import java.lang


class NTHeader(object, ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.pe.OffsetValidator):
    """
    A class to represent the IMAGE_NT_HEADERS32 and
     IMAGE_NT_HEADERS64 structs as defined in
     winnt.h.
 
     typedef struct _IMAGE_NT_HEADERS {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
     };
 
    """

    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    MAX_SANE_COUNT: int = 65536
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SIZEOF_SIGNATURE: int = 4
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, index: int, layout: ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout, advancedProcess: bool, parseCliHeaders: bool):
        """
        Constructs a new NT header.
        @param reader the binary reader
        @param index the index into the reader to the start of the NT header
        @param layout The {@link SectionLayout}
        @param advancedProcess if true, information outside of the base header will be processed
        @param parseCliHeaders if true, CLI headers are parsed (if present)
        @throws InvalidNTHeaderException if the bytes the specified index
        @throws IOException if an IO-related exception occurred
         do not constitute an accurate NT header.
        """
        ...



    def checkPointer(self, ptr: long) -> bool: ...

    def checkRVA(self, rva: long) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFileHeader(self) -> ghidra.app.util.bin.format.pe.FileHeader:
        """
        Returns the file header.
        @return the file header
        """
        ...

    def getName(self) -> unicode:
        """
        Returns the name to use when converting into a structure data type.
        @return the name to use when converting into a structure data type
        """
        ...

    def getOptionalHeader(self) -> ghidra.app.util.bin.format.pe.OptionalHeader:
        """
        Returns the optional header.
        @return the optional header
        """
        ...

    def hashCode(self) -> int: ...

    def isRVAResoltionSectionAligned(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def rvaToPointer(self, rva: long) -> long:
        """
        Converts a relative virtual address (RVA) into a pointer.
        @param rva the relative virtual address
        @return the pointer into binary image, 0 if not valid
        """
        ...

    @overload
    def rvaToPointer(self, rva: int) -> int:
        """
        Converts a relative virtual address (RVA) into a pointer.
        @param rva the relative virtual address
        @return the pointer into binary image, 0 if not valid
        """
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        @see ghidra.app.util.bin.StructConverter#toDataType()
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def vaToPointer(self, va: long) -> long:
        """
        Converts a virtual address (VA) into a pointer.
        @param va the virtual address
        @return the pointer into binary image, 0 if not valid
        """
        ...

    @overload
    def vaToPointer(self, va: int) -> int:
        """
        Converts a virtual address (VA) into a pointer.
        @param va the virtual address
        @return the pointer into binary image, 0 if not valid
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def RVAResoltionSectionAligned(self) -> bool: ...

    @property
    def fileHeader(self) -> ghidra.app.util.bin.format.pe.FileHeader: ...

    @property
    def name(self) -> unicode: ...

    @property
    def optionalHeader(self) -> ghidra.app.util.bin.format.pe.OptionalHeader: ...