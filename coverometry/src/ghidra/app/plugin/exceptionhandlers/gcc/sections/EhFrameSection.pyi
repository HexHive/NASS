from typing import List
import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.app.plugin.exceptionhandlers.gcc.sections
import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame
import ghidra.program.model.address
import java.lang


class EhFrameSection(ghidra.app.plugin.exceptionhandlers.gcc.sections.AbstractFrameSection):
    """
    Parses the call frame information exception handling structures within an '.eh_frame' 
     memory section.
    """

    EH_FRAME_BLOCK_NAME: unicode = u'.eh_frame'



    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program):
        """
        Constructor for an eh frame section.
        @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
        @param program the program containing this eh frame section.
        """
        ...



    def analyze(self, fdeTableCount: int) -> List[ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor]:
        """
        Analyzes and annotates the eh frame section.
        @param fdeTableCount the number of exception handler FDEs.
        @return the region descriptors for the eh frame section.
        @throws MemoryAccessException if memory couldn't be read/written while processing the eh frame.
        @throws AddressOutOfBoundsException if one or more expected addresses weren't in the program.
        @throws ExceptionHandlerFrameException if a problem was encountered determining eh frame data.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getCie(self, currAddress: ghidra.program.model.address.Address) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.Cie: ...

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

