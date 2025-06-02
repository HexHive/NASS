from typing import List
import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.app.plugin.exceptionhandlers.gcc.sections
import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame
import ghidra.program.model.address
import java.lang


class DebugFrameSection(ghidra.app.plugin.exceptionhandlers.gcc.sections.AbstractFrameSection):
    """
    Parses the exception handling structures within a '.debug_frame' memory section, which 
     contains call frame debugging information.
    """

    DEBUG_FRAME_BLOCK_NAME: unicode = u'.debug_frame'



    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program):
        """
        Constructor for a debug frame section.
        @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
        @param program the program containing this debug frame section.
        """
        ...



    def analyze(self) -> List[ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor]:
        """
        Analyzes and annotates the debug frame section.
        @return the region descriptors that compose the debug frame section.
        @throws MemoryAccessException if memory couldn't be read/written while processing the section.
        @throws AddressOutOfBoundsException if one or more expected addresses weren't in the program.
        @throws ExceptionHandlerFrameException if the FDE table can't be decoded.
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

