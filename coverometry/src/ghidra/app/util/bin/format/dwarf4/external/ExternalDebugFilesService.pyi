from typing import List
import ghidra.app.util.bin.format.dwarf4.external
import ghidra.formats.gfilesystem
import ghidra.util.task
import java.lang


class ExternalDebugFilesService(object):
    """
    A collection of SearchLocation that can be queried to find a
     DWARF external debug file, which is a second ELF binary that contains the debug information
     that was stripped from the original ELF binary.
    """





    def __init__(self, __a0: List[object]): ...



    def equals(self, __a0: object) -> bool: ...

    def findDebugFile(self, debugInfo: ghidra.app.util.bin.format.dwarf4.external.ExternalDebugInfo, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.FSRL:
        """
        Searches for the specified external debug file.
         <p>
         Returns the FSRL of a matching file, or null if not found.
        @param debugInfo information about the external debug file
        @param monitor {@link TaskMonitor}
        @return {@link FSRL} of found file, or {@code null} if not found
        @throws IOException if error
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getSearchLocations(self) -> List[ghidra.app.util.bin.format.dwarf4.external.SearchLocation]:
        """
        Returns the configured search locations.
        @return list of search locations
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

    @property
    def searchLocations(self) -> List[object]: ...