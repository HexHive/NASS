import ghidra.app.util.bin
import ghidra.file.formats.android.dex.format
import ghidra.file.formats.android.oat.oatclass
import java.lang


class OatClassFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getOatClass(__a0: ghidra.app.util.bin.BinaryReader, __a1: ghidra.file.formats.android.dex.format.ClassDataItem, __a2: unicode) -> ghidra.file.formats.android.oat.oatclass.OatClass: ...

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

