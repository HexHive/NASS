import ghidra.app.util.bin
import ghidra.program.model.listing
import java.lang


class BootImageUtil(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getOSVersionString(__a0: int) -> unicode: ...

    def hashCode(self) -> int: ...

    @overload
    @staticmethod
    def isBootImage(__a0: ghidra.app.util.bin.BinaryReader) -> bool: ...

    @overload
    @staticmethod
    def isBootImage(__a0: ghidra.program.model.listing.Program) -> bool: ...

    @overload
    @staticmethod
    def isVendorBootImage(__a0: ghidra.app.util.bin.BinaryReader) -> bool: ...

    @overload
    @staticmethod
    def isVendorBootImage(__a0: ghidra.program.model.listing.Program) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

