import ghidra.app.util.bin
import ghidra.app.util.bin.format.omf
import java.lang


class OmfRecord(object):
    ALIAS: int = -58
    BAKPAT: int = -78
    BLKDEF: int = 122
    BLKEND: int = 124
    CEXTDEF: int = -68
    COMDAT: int = -62
    COMDEF: int = -80
    COMENT: int = -120
    DEBSYM: int = 126
    END: int = -15
    ENDREC: int = 120
    EXTDEF: int = -116
    FIXUPP: int = -100
    GRPDEF: int = -102
    LCOMDEF: int = -72
    LEDATA: int = -96
    LEXTDEF: int = -76
    LHEADR: int = -126
    LIBDIC: int = -86
    LIBHED: int = -92
    LIBLOC: int = -88
    LIBNAM: int = -90
    LIDATA: int = -94
    LINNUM: int = -108
    LINSYM: int = -60
    LLNAMES: int = -54
    LNAMES: int = -106
    LOCSYM: int = -110
    LPUBDEF: int = -74
    MODEND: int = -118
    NBKPAT: int = -56
    OVLDEF: int = 118
    PEDATA: int = -124
    PIDATA: int = -122
    PUBDEF: int = -112
    REDATA: int = 114
    REGINT: int = 112
    RHEADR: int = 110
    RIDATA: int = 116
    SEGDEF: int = -104
    START: int = -16
    THEADR: int = -128
    TYPDEF: int = -114
    VENDEXT: int = -50
    VERNUM: int = -52



    def __init__(self): ...



    def calcCheckSum(self, reader: ghidra.app.util.bin.BinaryReader) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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
    def recordLength(self) -> int: ...

    @property
    def recordOffset(self) -> long: ...

    @property
    def recordType(self) -> int: ...