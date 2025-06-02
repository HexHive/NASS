import ghidra.util.task
import java.lang


class EhFrameHeaderSection(object):
    """
    Parses the exception handling structures within an '.eh_frame_hdr' memory section; contains 
     the frame header record and the FDE table.
    """

    EH_FRAME_HEADER_BLOCK_NAME: unicode = u'.eh_frame_hdr'



    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Constructor for an eh frame header section.
        @param program the program containing this eh frame header.
        """
        ...



    def analyze(self, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Analyzes and annotates the eh frame header.
        @param monitor a status monitor for indicating progress or allowing a task to be cancelled.
        @return the number of records in the FDE table or 0 if there was no EH frame header to analyze.
        @throws MemoryAccessException if memory couldn't be read/written while processing the header.
        @throws AddressOutOfBoundsException if one or more expected addresses weren't in the program.
        @throws ExceptionHandlerFrameException if the FDE table can't be decoded.
        """
        ...

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

