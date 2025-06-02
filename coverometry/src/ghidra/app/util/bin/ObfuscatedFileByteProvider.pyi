from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import java.io
import java.lang
import java.nio.file


class ObfuscatedFileByteProvider(ghidra.app.util.bin.FileByteProvider):
    """
    A ByteProvider that reads from an on-disk file, but obfuscates / de-obfuscates the
     contents of the file when reading / writing.
    """





    def __init__(self, file: java.io.File, fsrl: ghidra.formats.gfilesystem.FSRL, accessMode: java.nio.file.AccessMode):
        """
        Creates an instance of {@link ObfuscatedFileByteProvider}.
        @param file {@link File} to read from / write to
        @param fsrl {@link FSRL} identity of this file
        @param accessMode {@link AccessMode#READ} or {@link AccessMode#WRITE}
        @throws IOException if error
        """
        ...



    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAbsolutePath(self) -> unicode: ...

    def getAccessMode(self) -> java.nio.file.AccessMode:
        """
        Returns the access mode the file was opened with.
        @return {@link AccessMode} used to open file
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getFSRL(self) -> ghidra.formats.gfilesystem.FSRL: ...

    def getFile(self) -> java.io.File: ...

    def getInputStream(self, __a0: long) -> java.io.InputStream: ...

    def getName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    def isValidIndex(self, index: long) -> bool: ...

    def length(self) -> long: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readByte(self, index: long) -> int: ...

    @overload
    def readBytes(self, index: long, length: long) -> List[int]: ...

    @overload
    def readBytes(self, index: long, buffer: List[int], offset: int, length: int) -> int:
        """
        Read bytes at the specified index into the given byte array.
         <p>
         See {@link InputStream#read(byte[], int, int)}.
         <p>
        @param index file offset to start reading
        @param buffer byte array that will receive the bytes
        @param offset offset inside the byte array to place the bytes
        @param length number of bytes to read
        @return number of actual bytes read
        @throws IOException if error
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeByte(self, index: long, value: int) -> None: ...

    @overload
    def writeBytes(self, index: long, values: List[int]) -> None: ...

    @overload
    def writeBytes(self, index: long, buffer: List[int], offset: int, length: int) -> None:
        """
        Writes bytes to the specified offset in the file.
        @param index the location in the file to starting writing
        @param buffer bytes to write
        @param offset offset in the buffer byte array to start
        @param length number of bytes to write
        @throws IOException if bad {@link AccessMode} or other io error
        """
        ...

    @property
    def file(self) -> java.io.File: ...