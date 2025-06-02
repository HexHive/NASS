import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho.dyld
import ghidra.program.model.listing
import java.io
import java.lang


class DyldCacheUtils(object):
    """
    Utilities methods for working with Mach-O DYLD shared cache binaries.
    """






    class SplitDyldCache(object, java.io.Closeable):




        def __init__(self, __a0: ghidra.app.util.bin.ByteProvider, __a1: bool, __a2: ghidra.app.util.importer.MessageLog, __a3: ghidra.util.task.TaskMonitor): ...



        def close(self) -> None: ...

        def equals(self, __a0: object) -> bool: ...

        def getBaseAddress(self) -> long: ...

        def getClass(self) -> java.lang.Class: ...

        def getDyldCacheHeader(self, __a0: int) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader: ...

        def getLocalSymbolInfo(self) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsInfo: ...

        def getName(self, __a0: int) -> unicode: ...

        def getProvider(self, __a0: int) -> ghidra.app.util.bin.ByteProvider: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def size(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def baseAddress(self) -> long: ...

        @property
        def localSymbolInfo(self) -> ghidra.app.util.bin.format.macho.dyld.DyldCacheLocalSymbolsInfo: ...

    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @overload
    @staticmethod
    def isDyldCache(signature: unicode) -> bool:
        """
        Determines if the given signature represents a DYLD cache signature with an architecture we
         support.
        @param signature The DYLD cache signature
        @return True if the given signature represents a DYLD cache signature with an architecture we
         support; otherwise, false
        """
        ...

    @overload
    @staticmethod
    def isDyldCache(provider: ghidra.app.util.bin.ByteProvider) -> bool:
        """
        Determines if the given {@link ByteProvider} is a DYLD cache.
        @param provider The {@link ByteProvider}
        @return True if the given {@link ByteProvider} is a DYLD cache; otherwise, false
        """
        ...

    @overload
    @staticmethod
    def isDyldCache(program: ghidra.program.model.listing.Program) -> bool:
        """
        Determines if the given {@link Program} is a DYLD cache.
        @param program The {@link Program}
        @return True if the given {@link Program} is a DYLD cache; otherwise, false
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

