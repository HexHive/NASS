import ghidra.app.util.bin
import ghidra.file.formats.android.dex.format
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class DexHeaderFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    @staticmethod
    def getDexHeader(__a0: ghidra.app.util.bin.BinaryReader) -> ghidra.file.formats.android.dex.format.DexHeader: ...

    @overload
    @staticmethod
    def getDexHeader(__a0: ghidra.program.model.listing.Program) -> ghidra.file.formats.android.dex.format.DexHeader: ...

    @overload
    @staticmethod
    def getDexHeader(__a0: ghidra.app.util.bin.BinaryReader, __a1: bool) -> ghidra.file.formats.android.dex.format.DexHeader: ...

    @overload
    @staticmethod
    def getDexHeader(__a0: ghidra.app.util.bin.ByteProvider, __a1: bool) -> ghidra.file.formats.android.dex.format.DexHeader: ...

    @overload
    @staticmethod
    def getDexHeader(__a0: ghidra.program.model.listing.Program, __a1: ghidra.program.model.address.Address) -> ghidra.file.formats.android.dex.format.DexHeader: ...

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

