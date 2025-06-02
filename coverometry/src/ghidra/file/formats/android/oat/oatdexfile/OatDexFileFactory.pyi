import ghidra.app.util.bin
import ghidra.file.formats.android.oat.bundle
import ghidra.file.formats.android.oat.oatdexfile
import java.lang


class OatDexFileFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getOatDexFile(__a0: ghidra.app.util.bin.BinaryReader, __a1: unicode, __a2: ghidra.file.formats.android.oat.bundle.OatBundle) -> ghidra.file.formats.android.oat.oatdexfile.OatDexFile: ...

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

