import ghidra.app.util.bin
import ghidra.file.formats.android.bootimg
import java.lang


class VendorBootImageHeaderFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    @staticmethod
    def getVendorBootImageHeader(__a0: ghidra.app.util.bin.BinaryReader) -> ghidra.file.formats.android.bootimg.VendorBootImageHeader: ...

    @overload
    @staticmethod
    def getVendorBootImageHeader(__a0: ghidra.app.util.bin.ByteProvider, __a1: bool) -> ghidra.file.formats.android.bootimg.VendorBootImageHeader: ...

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

