import ghidra.file.formats.android.art
import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class ArtUtilities(object):




    def __init__(self): ...



    @staticmethod
    def adjustForThumbAsNeeded(__a0: ghidra.file.formats.android.art.ArtHeader, __a1: ghidra.program.model.listing.Program, __a2: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

    def equals(self, __a0: object) -> bool: ...

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

