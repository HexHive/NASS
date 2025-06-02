from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import java.io
import java.lang


class RangeMappedByteProvider(object, ghidra.app.util.bin.ByteProvider):
    """
    A ByteProvider that is a concatenation of sub-ranges of another ByteProvider, also
     allowing for non-initialized (sparse) regions.
  
     Not thread-safe when ranges are being added.
 
     Does not assume ownership of wrapped ByteProvider.
    """

    EMPTY_BYTEPROVIDER: ghidra.app.util.bin.ByteProvider = ghidra.app.util.bin.EmptyByteProvider@5a458540



    def __init__(self, provider: ghidra.app.util.bin.ByteProvider, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Creates a new {@link RangeMappedByteProvider}.
        @param provider {@link ByteProvider} to wrap
        @param fsrl {@link FSRL} of this new byte provider
        """
        ...



    def addRange(self, offset: long, rangeLen: long) -> None:
        """
        Adds a range to the current end of this instance.
         <p>
         If the new range immediately follows the previous range, the new range is merged
         into the previous entry.
        @param offset long byte offset in the delegate ByteProvider, -1 indicates a sparse
         range with no storage
        @param rangeLen long length of the range in the delegate ByteProvider
        """
        ...

    def addSparseRange(self, rangeLen: long) -> None:
        """
        Adds a sparse range to the current end of this instance.
        @param rangeLen long length of the sparse range
        """
        ...

    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAbsolutePath(self) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    def getFSRL(self) -> ghidra.formats.gfilesystem.FSRL: ...

    def getFile(self) -> java.io.File: ...

    def getInputStream(self, __a0: long) -> java.io.InputStream: ...

    def getName(self) -> unicode: ...

    def getRangeCount(self) -> int:
        """
        Return the number of ranges.  Adjacent ranges that were merged
         will count as a single range.
        @return number of ranges
        """
        ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    def isValidIndex(self, index: long) -> bool: ...

    def length(self) -> long: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readByte(self, index: long) -> int: ...

    @overload
    def readBytes(self, index: long, longCount: long) -> List[int]: ...

    @overload
    def readBytes(self, index: long, buffer: List[int], offset: int, len: int) -> int:
        """
        Read bytes at the specified index into the given byte array.
         <p>
         See {@link InputStream#read(byte[], int, int)}.
         <p>
        @param index file offset to start reading
        @param buffer byte array that will receive the bytes
        @param offset offset inside the byte array to place the bytes
        @param len number of bytes to read
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

    @property
    def FSRL(self) -> ghidra.formats.gfilesystem.FSRL: ...

    @property
    def absolutePath(self) -> unicode: ...

    @property
    def empty(self) -> bool: ...

    @property
    def file(self) -> java.io.File: ...

    @property
    def name(self) -> unicode: ...

    @property
    def rangeCount(self) -> int: ...