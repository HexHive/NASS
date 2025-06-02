import ghidra.app.util.bin.format.coff
import ghidra.app.util.bin.format.coff.relocation
import ghidra.program.model.address
import ghidra.program.model.reloc
import ghidra.util.classfinder
import java.lang


class CoffRelocationHandler(ghidra.util.classfinder.ExtensionPoint, object):
    """
    An abstract class used to perform COFF relocations.  Classes should extend this class to
     provide relocations in a machine/processor specific way.
    """









    def canRelocate(self, fileHeader: ghidra.app.util.bin.format.coff.CoffFileHeader) -> bool:
        """
        Checks to see whether or not an instance of this COFF relocation hander can handle 
         relocating the COFF defined by the provided file header.
        @param fileHeader The file header associated with the COFF to relocate.
        @return True if this relocation handler can do the relocation; otherwise, false.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def relocate(self, address: ghidra.program.model.address.Address, relocation: ghidra.app.util.bin.format.coff.CoffRelocation, relocationContext: ghidra.app.util.bin.format.coff.relocation.CoffRelocationContext) -> ghidra.program.model.reloc.RelocationResult:
        """
        Performs a relocation at the specified address.
        @param address The address at which to perform the relocation.
        @param relocation The relocation information to use to perform the relocation.
        @param relocationContext relocation context data
        @return applied relocation result (conveys status and applied byte-length)
        @throws MemoryAccessException If there is a problem accessing memory during the relocation.
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

