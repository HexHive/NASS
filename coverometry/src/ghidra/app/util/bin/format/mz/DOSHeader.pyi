from typing import List
import ghidra.app.util.bin.format.mz
import ghidra.program.model.data
import ghidra.util
import java.io
import java.lang


class DOSHeader(ghidra.app.util.bin.format.mz.OldDOSHeader):
    """
    This class represents the IMAGE_DOS_HEADER struct
     as defined in winnt.h.
 
 
     typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
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
         WORD   e_res[4];                    // Reserved words
         WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
         WORD   e_oeminfo;                   // OEM information; e_oemid specific
         WORD   e_res2[10];                  // Reserved words							// MANDATORY
         LONG   e_lfanew;                    // File address of new exe header
     } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
 
    """

    NAME: unicode = u'IMAGE_DOS_HEADER'
    SIZEOF_DOS_HEADER: int = 64



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Constructs a new DOS header.
        @param reader the binary reader
        @throws IOException if there was an IO-related error
        """
        ...



    def decrementStub(self, start: int) -> None: ...

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

    def e_lfanew(self) -> int:
        """
        Returns the file address of new EXE header.
        @return the file address of new EXE header
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

    def e_oemid(self) -> int:
        """
        Returns the OEM identifier (for e_oeminfo).
        @return the OEM identifier (for e_oeminfo)
        """
        ...

    def e_oeminfo(self) -> int:
        """
        Returns the OEM information; e_oemid specific.
        @return the OEM information; e_oemid specific
        """
        ...

    def e_ovno(self) -> int:
        """
        Returns the overlay number.
        @return the overlay number
        """
        ...

    def e_res(self) -> List[int]:
        """
        Returns the reserved words.
        @return the reserved words
        """
        ...

    def e_res2(self) -> List[int]:
        """
        Returns the reserved words (2).
        @return the reserved words (2)
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

    def getName(self) -> unicode:
        """
        Helper to override the value of name
        @return The name of the header
        """
        ...

    def getProcessorName(self) -> unicode:
        """
        Returns the processor name.
        @return the processor name
        """
        ...

    def getProgramLen(self) -> int:
        """
        Returns the length (in bytes) of the DOS
         program.
         <p>
         In other words:
         <code>e_lfanew() - SIZEOF_DOS_HEADER</code>
        @return the length (in bytes)
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

    def write(self, raf: java.io.RandomAccessFile, dc: ghidra.util.DataConverter) -> None:
        """
        @see ghidra.app.util.bin.format.Writeable#write(java.io.RandomAccessFile, ghidra.util.DataConverter)
        """
        ...

    @property
    def name(self) -> unicode: ...

    @property
    def programLen(self) -> int: ...