import ghidra.app.util.bin
import ghidra.app.util.bin.format
import ghidra.program.model.data
import ghidra.util
import java.io
import java.lang


class OldDOSHeader(object, ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.format.Writeable):
    """
    This class represents a DOS Header
 
 
         WORD   e_magic;                     // Magic number								// MANDATORY
         WORD   e_cblp;                      // Bytes on last page of file
         WORD   e_cp;                        // Pages in file
         WORD   e_crlc;                      // Relocations
         WORD   e_cparhdr;                   // Size of header in paragraphs
         WORD   e_minalloc;                  // Minimum extra paragraphs needed
         WORD   e_maxalloc;                  // Maximum extra paragraphs needed
         WORD   e_ss;                        // Initial (relative) SS value
         WORD   e_sp;                        // Initial SP value
         WORD   e_csum;                      // Checksum
         WORD   e_ip;                        // Initial IP value
         WORD   e_cs;                        // Initial (relative) CS value
         WORD   e_lfarlc;                    // File address of relocation table
         WORD   e_ovno;                      // Overlay number
     
 
    """

    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    IMAGE_DOS_SIGNATURE: int = 23117
    NAME: unicode = u'OLD_IMAGE_DOS_HEADER'
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
        Constructs a new DOS header.
        @param reader the binary reader
        @throws IOException if there was an IO-related error
        """
        ...



    def e_cblp(self) -> int:
        """
        Returns the number of bytes on the last page of file.
        @return the number of bytes on the last page of the file
        """
        ...

    def e_cp(self) -> int:
        """
        Returns the number of pages in the file.
        @return the number of pages in the file
        """
        ...

    def e_cparhdr(self) -> int:
        """
        Returns the size of header in paragraphs.
        @return the size of header in paragraphs
        """
        ...

    def e_crlc(self) -> int:
        """
        Returns the number of relocations.
        @return the number of relocations
        """
        ...

    def e_cs(self) -> int:
        """
        Returns the initial (relative) CS value.
        @return the initial (relative) CS value
        """
        ...

    def e_csum(self) -> int:
        """
        Returns the checksum.
        @return the checksum
        """
        ...

    def e_ip(self) -> int:
        """
        Returns the initial IP value.
        @return the initial IP value
        """
        ...

    def e_lfarlc(self) -> int:
        """
        Returns the file address of relocation table.
        @return the file address of relocation table
        """
        ...

    def e_magic(self) -> int:
        """
        Returns the magic number.
        @return the magic number
        """
        ...

    def e_maxalloc(self) -> int:
        """
        Returns the maximum extra paragraphs needed.
        @return the maximum extra paragraphs needed
        """
        ...

    def e_minalloc(self) -> int:
        """
        Returns the minimum extra paragraphs needed.
        @return the minimum extra paragraphs needed
        """
        ...

    def e_ovno(self) -> int:
        """
        Returns the overlay number.
        @return the overlay number
        """
        ...

    def e_sp(self) -> int:
        """
        Returns the initial SP value.
        @return the initial SP value
        """
        ...

    def e_ss(self) -> int:
        """
        Returns the initial (relative) SS value.
        @return the initial (relative) SS value
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getProcessorName(self) -> unicode:
        """
        Returns the processor name.
        @return the processor name
        """
        ...

    def hasNewExeHeader(self) -> bool:
        """
        Returns true if a new EXE header exists.
        @return true if a new EXE header exists
        """
        ...

    def hasPeHeader(self) -> bool:
        """
        Returns true if a PE header exists.
        @return true if a PE header exists
        """
        ...

    def hashCode(self) -> int: ...

    def isDosSignature(self) -> bool:
        """
        Returns true if the DOS magic number is correct
        @return true if the DOS magic number is correct
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

    def write(self, raf: java.io.RandomAccessFile, dc: ghidra.util.DataConverter) -> None: ...

    @property
    def dosSignature(self) -> bool: ...

    @property
    def processorName(self) -> unicode: ...