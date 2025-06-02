from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.pe.cli.blobs
import ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig
import ghidra.app.util.bin.format.pe.cli.blobs.CliSigStandAloneMethod
import ghidra.app.util.bin.format.pe.cli.streams
import ghidra.program.model.data
import java.lang
import java.util


class CliSigStandAloneMethod(ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig):





    class CallingConvention(java.lang.Enum):
        C: ghidra.app.util.bin.format.pe.cli.blobs.CliSigStandAloneMethod.CallingConvention = C
        FASTCALL: ghidra.app.util.bin.format.pe.cli.blobs.CliSigStandAloneMethod.CallingConvention = FASTCALL
        MANAGED: ghidra.app.util.bin.format.pe.cli.blobs.CliSigStandAloneMethod.CallingConvention = MANAGED
        STDCALL: ghidra.app.util.bin.format.pe.cli.blobs.CliSigStandAloneMethod.CallingConvention = STDCALL
        THISCALL: ghidra.app.util.bin.format.pe.cli.blobs.CliSigStandAloneMethod.CallingConvention = THISCALL







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.app.util.bin.format.pe.cli.blobs.CliSigStandAloneMethod.CallingConvention: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.app.util.bin.format.pe.cli.blobs.CliSigStandAloneMethod.CallingConvention]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    def __init__(self, blob: ghidra.app.util.bin.format.pe.cli.blobs.CliBlob): ...



    @staticmethod
    def convertTypeCodeToDataType(typeCode: ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliElementType) -> ghidra.program.model.data.DataType: ...

    @overload
    @staticmethod
    def decodeCompressedSigned(codedSize: int) -> int: ...

    @overload
    @staticmethod
    def decodeCompressedSigned(codedSize: int) -> int: ...

    @overload
    @staticmethod
    def decodeCompressedSigned(codedSize: int) -> int: ...

    @staticmethod
    def decodeCompressedSignedInt(reader: ghidra.app.util.bin.BinaryReader) -> int: ...

    @overload
    @staticmethod
    def decodeCompressedUnsigned(codedSize: int) -> int: ...

    @overload
    @staticmethod
    def decodeCompressedUnsigned(codedSize: int) -> int: ...

    @overload
    @staticmethod
    def decodeCompressedUnsigned(codedSize: int) -> int: ...

    @staticmethod
    def decodeCompressedUnsignedInt(reader: ghidra.app.util.bin.BinaryReader) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getCallingConvention(self) -> ghidra.app.util.bin.format.pe.cli.blobs.CliSigStandAloneMethod.CallingConvention: ...

    def getClass(self) -> java.lang.Class: ...

    def getContents(self) -> List[int]:
        """
        Gets the blob's contents.
        @return the blob's contents.  Could be null if there was a problem reading the 
           contents.
        """
        ...

    def getContentsComment(self) -> unicode: ...

    def getContentsDataType(self) -> ghidra.program.model.data.DataType: ...

    def getContentsName(self) -> unicode: ...

    def getContentsReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Gets a new binary reader positioned at the start of this blob's contents.
        @return A new binary reader positioned at the start of this blob's contents.
        """
        ...

    def getContentsSize(self) -> int:
        """
        Gets the blob's contents size in bytes.
        @return The blob's contents size in bytes.
        """
        ...

    @staticmethod
    def getDataTypeForBytes(numBytes: int) -> ghidra.program.model.data.DataType: ...

    def getName(self) -> unicode:
        """
        Gets the name of this blob.
        @return The name of this blob.
        """
        ...

    def getParams(self) -> List[ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliParam]: ...

    @overload
    def getRepresentation(self) -> unicode: ...

    @overload
    def getRepresentation(self, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata) -> unicode: ...

    def getRepresentationCommon(self, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata, isShort: bool) -> unicode: ...

    def getReturnType(self) -> ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliRetType: ...

    @overload
    def getShortRepresentation(self) -> unicode: ...

    @overload
    def getShortRepresentation(self, stream: ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata) -> unicode: ...

    def getSize(self) -> int:
        """
        Gets the blob's size in bytes (includes all fields).
        @return The blob's size in bytes.
        """
        ...

    def getSizeDataType(self) -> ghidra.program.model.data.DataType:
        """
        Gets the proper data type for the blob's size field.
        @return The proper data type for the blob's size field.
        """
        ...

    def getStreamIndex(self) -> int:
        """
        Gets the index into the blob stream of this blob.
        @return The index into the blob stream of this blob.
        """
        ...

    def hasExplicitThis(self) -> bool: ...

    def hasThis(self) -> bool: ...

    def hasVarArgs(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isLittleEndian(self) -> bool:
        """
        Checks to see whether or not this blob is little endian.
        @return True if this blob is little endian; false if big endian.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readCliType(self, reader: ghidra.app.util.bin.BinaryReader) -> ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliSigType: ...

    @staticmethod
    def testSizeDecoding() -> None: ...

    @overload
    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    @overload
    def toDataType(self, dtm: ghidra.program.model.data.DataTypeManager) -> ghidra.program.model.data.DataType:
        """
        Create CLI Blob structure.
         NOTE: This form is provided to reduce resolution time when target datatype manager is known.
        @param dtm datatype manager or null if target datatype manager is unknown.
        @return blob structure
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
    def callingConvention(self) -> ghidra.app.util.bin.format.pe.cli.blobs.CliSigStandAloneMethod.CallingConvention: ...

    @property
    def contentsComment(self) -> unicode: ...

    @property
    def contentsDataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def contentsName(self) -> unicode: ...

    @property
    def params(self) -> List[ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliParam]: ...

    @property
    def returnType(self) -> ghidra.app.util.bin.format.pe.cli.blobs.CliAbstractSig.CliRetType: ...