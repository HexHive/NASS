from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.omf
import java.lang


class OmfData(ghidra.app.util.bin.format.omf.OmfRecord, java.lang.Comparable):
    """
    Object representing data loaded directly into the final image.
    """





    def __init__(self): ...



    def calcCheckSum(self, reader: ghidra.app.util.bin.BinaryReader) -> int: ...

    @overload
    def compareTo(self, o: ghidra.app.util.bin.format.omf.OmfData) -> int:
        """
        Compare datablocks by data offset
        @return a value less than 0 for lower address, 0 for same address, or greater than 0 for
           higher address
        """
        ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getByteArray(self, reader: ghidra.app.util.bin.BinaryReader) -> List[int]:
        """
        Create a byte array holding the data represented by this object. The length
         of the byte array should exactly match the value returned by getLength()
        @param reader is for pulling bytes directly from the binary image
        @return allocated and filled byte array
        @throws IOException for problems accessing data through the reader
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDataOffset(self) -> long:
        """
        @return the starting offset, within the loaded image, of this data
        """
        ...

    def getLength(self) -> int:
        """
        @return the length of this data in bytes
        """
        ...

    def getRecordLength(self) -> int: ...

    @staticmethod
    def getRecordName(type: int) -> unicode:
        """
        Gets the name of the given record type
        @param type The record type
        @return The name of the given record type
        """
        ...

    def getRecordOffset(self) -> long: ...

    def getRecordType(self) -> int: ...

    def getSegmentIndex(self) -> int:
        """
        @return get the segments index for this datablock
        """
        ...

    def hasBigFields(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isAllZeroes(self) -> bool:
        """
        @return true if this is a block entirely of zeroes
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readCheckSumByte(self, reader: ghidra.app.util.bin.BinaryReader) -> None: ...

    @staticmethod
    def readIndex(reader: ghidra.app.util.bin.BinaryReader) -> int: ...

    @staticmethod
    def readInt1Or2(reader: ghidra.app.util.bin.BinaryReader, isBig: bool) -> int: ...

    @staticmethod
    def readInt2Or4(reader: ghidra.app.util.bin.BinaryReader, isBig: bool) -> int: ...

    @staticmethod
    def readRecord(reader: ghidra.app.util.bin.BinaryReader) -> ghidra.app.util.bin.format.omf.OmfRecord: ...

    def readRecordHeader(self, reader: ghidra.app.util.bin.BinaryReader) -> None: ...

    @staticmethod
    def readString(reader: ghidra.app.util.bin.BinaryReader) -> unicode:
        """
        Read the OMF string format: 1-byte length, followed by that many ascii characters
        @param reader A {@link BinaryReader} positioned at the start of the string
        @return the read OMF string
        @throws IOException if an IO-related error occurred
        """
        ...

    def toString(self) -> unicode: ...

    def validCheckSum(self, reader: ghidra.app.util.bin.BinaryReader) -> bool: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def allZeroes(self) -> bool: ...

    @property
    def dataOffset(self) -> long: ...

    @property
    def length(self) -> int: ...

    @property
    def segmentIndex(self) -> int: ...