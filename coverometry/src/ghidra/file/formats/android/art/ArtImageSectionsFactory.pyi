import ghidra.app.util.bin
import ghidra.file.formats.android.art
import java.lang


class ArtImageSectionsFactory(object):




    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getArtImageSections(__a0: ghidra.app.util.bin.BinaryReader, __a1: ghidra.file.formats.android.art.ArtHeader) -> ghidra.file.formats.android.art.ArtImageSections: ...

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

