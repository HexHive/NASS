from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import java.io
import java.lang


class RefdByteProvider(object, ghidra.app.util.bin.ByteProvider):
    """
    A ByteProvider along with a FileSystemRef to keep the filesystem pinned
     in memory.
 
     The caller is responsible for #close() this object, which releases
     the FilesystemRef.
    """

    EMPTY_BYTEPROVIDER: ghidra.app.util.bin.ByteProvider = ghidra.app.util.bin.EmptyByteProvider@5a458540



    def __init__(self, fsRef: ghidra.formats.gfilesystem.FileSystemRef, provider: ghidra.app.util.bin.ByteProvider, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Creates a RefdByteProvider instance, taking ownership of the supplied FileSystemRef.
        @param fsRef {@link FileSystemRef} that contains the specified ByteProvider
        @param provider {@link ByteProvider} inside the filesystem held open by the ref
        @param fsrl {@link FSRL} identity of this new ByteProvider
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

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    def isValidIndex(self, index: long) -> bool: ...

    def length(self) -> long: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readByte(self, index: long) -> int: ...

    def readBytes(self, index: long, length: long) -> List[int]: ...

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