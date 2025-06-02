import ghidra.app.util.bin
import ghidra.file.formats.android.fbpk
import java.lang


class FBPK_Factory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getFBPK(__a0: ghidra.app.util.bin.BinaryReader) -> ghidra.file.formats.android.fbpk.FBPK: ...

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

