import ghidra.app.util.bin
import ghidra.file.formats.android.oat.quickmethod
import java.lang


class OatQuickMethodHeaderFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getOatQuickMethodHeader(__a0: ghidra.app.util.bin.BinaryReader, __a1: unicode) -> ghidra.file.formats.android.oat.quickmethod.OatQuickMethodHeader: ...

    @staticmethod
    def getOatQuickMethodHeaderSize(__a0: unicode) -> int: ...

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

