import ghidra.app.util.bin
import ghidra.app.util.bin.format.omf
import java.lang


class OmfCommentRecord(ghidra.app.util.bin.format.omf.OmfRecord):
    COMMENT_CLASS_DEFAULT_LIBRARY: int = -97
    COMMENT_CLASS_LIBMOD: int = -93
    COMMENT_CLASS_MICROSOFT_SETTINGS: int = -99
    COMMENT_CLASS_TRANSLATOR: int = 0
    COMMENT_CLASS_WATCOM_SETTINGS: int = -101



    def __init__(self, reader: ghidra.app.util.bin.BinaryReader): ...



    def calcCheckSum(self, reader: ghidra.app.util.bin.BinaryReader) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCommentClass(self) -> int: ...

    def getCommentType(self) -> int: ...

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

    def getValue(self) -> unicode: ...

    def hasBigFields(self) -> bool: ...

    def hashCode(self) -> int: ...

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
    def commentClass(self) -> int: ...

    @property
    def commentType(self) -> int: ...

    @property
    def value(self) -> unicode: ...