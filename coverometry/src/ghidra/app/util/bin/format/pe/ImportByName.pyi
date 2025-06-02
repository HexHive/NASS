from typing import List
import ghidra.app.util.bin
import ghidra.program.model.data
import ghidra.util
import java.lang


class ImportByName(object, ghidra.app.util.bin.StructConverter, ghidra.app.util.bin.ByteArrayConverter):
    """
    A class to represent the IMAGE_IMPORT_BY_NAME
     data structure defined in winnt.h.

 
     typedef struct _IMAGE_IMPORT_BY_NAME {
         WORD    Hint;
         BYTE    Name[1];
     };
 
    """

    ASCII: ghidra.program.model.data.DataType = char
    BYTE: ghidra.program.model.data.DataType = byte
    DWORD: ghidra.program.model.data.DataType = dword
    IBO32: ghidra.program.model.data.DataType = IBO32DataType: typedef ImageBaseOffset32 pointer32
    IBO64: ghidra.program.model.data.DataType = IBO64DataType: typedef ImageBaseOffset64 pointer64
    NAME: unicode = u'IMAGE_IMPORT_BY_NAME'
    POINTER: ghidra.program.model.data.DataType = pointer
    QWORD: ghidra.program.model.data.DataType = qword
    SLEB128: ghidra.program.model.data.SignedLeb128DataType = sleb128
    STRING: ghidra.program.model.data.DataType = string
    ULEB128: ghidra.program.model.data.UnsignedLeb128DataType = uleb128
    UTF16: ghidra.program.model.data.DataType = unicode
    UTF8: ghidra.program.model.data.DataType = string-utf8
    VOID: ghidra.program.model.data.DataType = void
    WORD: ghidra.program.model.data.DataType = word



    def __init__(self, hint: int, name: unicode):
        """
        @param hint the import hint (ordinal)
        @param name the name of the imported function.
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getHint(self) -> int:
        """
        @return the export ordinal for the imported function
        """
        ...

    def getName(self) -> unicode:
        """
        Returns an ASCIIZ string with the name of the imported function.
        @return an ASCIIZ string with the name of the imported function
        """
        ...

    def getSizeOf(self) -> int:
        """
        Returns the actual number of bytes consumed by this structure in memory.
        @return the actual number of bytes consumed by this structure in memory
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toBytes(self, dc: ghidra.util.DataConverter) -> List[int]:
        """
        @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
        """
        ...

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
    def hint(self) -> int: ...

    @property
    def name(self) -> unicode: ...

    @property
    def sizeOf(self) -> int: ...