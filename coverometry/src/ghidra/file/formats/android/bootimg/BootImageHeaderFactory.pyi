import ghidra.app.util.bin
import ghidra.file.formats.android.bootimg
import java.lang


class BootImageHeaderFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @overload
    @staticmethod
    def getBootImageHeader(__a0: ghidra.app.util.bin.BinaryReader) -> ghidra.file.formats.android.bootimg.BootImageHeader: ...

    @overload
    @staticmethod
    def getBootImageHeader(__a0: ghidra.app.util.bin.ByteProvider, __a1: bool) -> ghidra.file.formats.android.bootimg.BootImageHeader: ...

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

