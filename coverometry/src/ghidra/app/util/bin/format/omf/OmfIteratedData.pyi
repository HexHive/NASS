from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.omf
import java.lang


class OmfIteratedData(ghidra.app.util.bin.format.omf.OmfData):
    MAX_ITERATED_FILL: int = 1048576




    class DataBlock(object):




        def __init__(self): ...



        def equals(self, __a0: object) -> bool: ...

        def fillBuffer(self, __a0: List[int], __a1: int) -> int: ...

        def getClass(self) -> java.lang.Class: ...

        def getLength(self) -> int: ...

        def hashCode(self) -> int: ...

        def isAllZeroes(self) -> bool: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        @staticmethod
        def read(__a0: ghidra.app.util.bin.BinaryReader, __a1: bool) -> ghidra.app.util.bin.format.omf.OmfIteratedData.DataBlock: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def allZeroes(self) -> bool: ...

        @property
        def length(self) -> int: ...

    def __init__(self, reader: ghidra.app.util.bin.BinaryReader): ...



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

    def getByteArray(self, reader: ghidra.app.util.bin.BinaryReader) -> List[int]: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataOffset(self) -> long:
        """
        @return the starting offset, within the loaded image, of this data
        """
        ...

    def getLength(self) -> int: ...

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

    def isAllZeroes(self) -> bool: ...

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
    def length(self) -> int: ...