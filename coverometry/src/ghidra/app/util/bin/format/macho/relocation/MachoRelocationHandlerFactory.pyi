import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.relocation
import java.lang


class MachoRelocationHandlerFactory(object):
    """
    A class that gets the appropriate Mach-O relocation handler for a specific Mach-O file
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getHandler(header: ghidra.app.util.bin.format.macho.MachHeader) -> ghidra.app.util.bin.format.macho.relocation.MachoRelocationHandler:
        """
        Gets the appropriate Mach-O relocation handler that is capable of relocating the Mach-O that 
         is defined by the given Mach-O header
        @param header The header associated with the Mach-O to relocate
        @return The appropriate Mach-O relocation handler that is capable of relocating the Mach-O 
           that is defined by the given Mach-O header.  Could return null if no such handler was
           found.
        """
        ...

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

