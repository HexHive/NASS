from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.omf
import ghidra.app.util.bin.format.omf.OmfLibraryRecord
import ghidra.util.task
import java.lang


class OmfLibraryRecord(ghidra.app.util.bin.format.omf.OmfRecord):





    class MemberHeader(object):
        machineName: unicode
        name: unicode
        payloadOffset: long
        size: long
        translator: unicode



        def __init__(self): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader): ...



    def calcCheckSum(self, reader: ghidra.app.util.bin.BinaryReader) -> int: ...

    @staticmethod
    def checkMagicNumber(reader: ghidra.app.util.bin.BinaryReader) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getMemberHeaders(self) -> List[ghidra.app.util.bin.format.omf.OmfLibraryRecord.MemberHeader]: ...

    def getPageSize(self) -> int: ...

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

    def hasBigFields(self) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def parse(reader: ghidra.app.util.bin.BinaryReader, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.format.omf.OmfLibraryRecord: ...

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
    def memberHeaders(self) -> java.util.ArrayList: ...

    @property
    def pageSize(self) -> int: ...