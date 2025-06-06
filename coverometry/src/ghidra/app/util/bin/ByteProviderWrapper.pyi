from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import java.io
import java.lang


class ByteProviderWrapper(object, ghidra.app.util.bin.ByteProvider):
    """
    A ByteProvider constrained to a sub-section of an existing ByteProvider.
    """

    EMPTY_BYTEPROVIDER: ghidra.app.util.bin.ByteProvider = ghidra.app.util.bin.EmptyByteProvider@5a458540



    @overload
    def __init__(self, provider: ghidra.app.util.bin.ByteProvider, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Creates a wrapper around a {@link ByteProvider} that contains the same bytes as the specified
         provider, but with a new {@link FSRL} identity.
         <p>
        @param provider {@link ByteProvider} to wrap
        @param fsrl {@link FSRL} identity for the instance
        @throws IOException if error
        """
        ...

    @overload
    def __init__(self, provider: ghidra.app.util.bin.ByteProvider, subOffset: long, subLength: long):
        """
        Constructs a {@link ByteProviderWrapper} around the specified {@link ByteProvider},
         constrained to a subsection of the provider.
        @param provider the {@link ByteProvider} to wrap
        @param subOffset the offset in the {@link ByteProvider} of where to start the new
           {@link ByteProviderWrapper}
        @param subLength the length of the new {@link ByteProviderWrapper}
        """
        ...

    @overload
    def __init__(self, provider: ghidra.app.util.bin.ByteProvider, subOffset: long, subLength: long, fsrl: ghidra.formats.gfilesystem.FSRL):
        """
        Constructs a {@link ByteProviderWrapper} around the specified {@link ByteProvider},
         constrained to a subsection of the provider.
        @param provider the {@link ByteProvider} to wrap
        @param subOffset the offset in the {@link ByteProvider} of where to start the new
           {@link ByteProviderWrapper}
        @param subLength the length of the new {@link ByteProviderWrapper}
        @param fsrl {@link FSRL} identity of the file this ByteProvider represents
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