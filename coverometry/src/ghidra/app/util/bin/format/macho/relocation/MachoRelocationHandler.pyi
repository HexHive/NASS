import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.relocation
import ghidra.program.model.reloc
import ghidra.util.classfinder
import java.lang


class MachoRelocationHandler(object, ghidra.util.classfinder.ExtensionPoint):
    """
    An abstract class used to perform Mach-O relocations.  Classes should extend this class to
     provide relocations in a machine/processor specific way.
    """





    def __init__(self): ...



    def canRelocate(self, header: ghidra.app.util.bin.format.macho.MachHeader) -> bool:
        """
        Checks to see whether or not an instance of this Mach-O relocation handler can handle 
         relocating the Mach-O defined by the provided file header
        @param header The header associated with the Mach-O to relocate
        @return True if this relocation handler can do the relocation; otherwise, false
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isPairedRelocation(self, relocation: ghidra.app.util.bin.format.macho.RelocationInfo) -> bool:
        """
        Checks to see if the given relocation is a "paired" relocation.  A paired relocation has a 
         certain expectation from the relocation that follows it.
        @param relocation The relocation to check
        @return True if the given relocation is a "paired" relocation; otherwise, false
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def read(relocation: ghidra.app.util.bin.format.macho.relocation.MachoRelocation) -> long:
        """
        Reads bytes at the given address.  The size of the read is determined by the length of the 
         relocation info.
        @param relocation The relocation to read
        @return The read bytes
        @throws MemoryAccessException If there is a problem accessing memory during the read
        """
        ...

    def relocate(self, relocation: ghidra.app.util.bin.format.macho.relocation.MachoRelocation) -> ghidra.program.model.reloc.RelocationResult:
        """
        Performs a relocation
        @param relocation The relocation to perform
        @return applied relocation result
        @throws MemoryAccessException If there is a problem accessing memory during the relocation
        @throws RelocationException if supported relocation encountered an error during processing.
         This exception should be thrown in place of returning {@link RelocationResult#FAILURE} or
         a status of {@link Status#FAILURE} which will facilitate a failure reason via 
         {@link RelocationException#getMessage()}.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @staticmethod
    def write(relocation: ghidra.app.util.bin.format.macho.relocation.MachoRelocation, value: long) -> int:
        """
        Writes bytes at the given address.  The size of the write is determined by the length of the 
         relocation info.
        @param relocation The relocation to write
        @param value The value to write
        @return number of bytes written
        @throws MemoryAccessException If there is a problem accessing memory during the write
        """
        ...

