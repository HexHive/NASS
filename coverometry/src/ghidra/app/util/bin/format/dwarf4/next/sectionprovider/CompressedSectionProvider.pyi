from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class CompressedSectionProvider(object, ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DWARFSectionProvider):
    """
    A wrapper around another DWARFSectionProvider, this provider
     fetches DWARF section data that has been compressed and stored in sections in the underlying 
     DWARFSectionProvider.
 
    """





    def __init__(self, sp: ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DWARFSectionProvider): ...



    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getSectionAsByteProvider(self, sectionName: unicode, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider: ...

    def hasSection(self, sectionNames: List[unicode]) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def updateProgramInfo(self, __a0: ghidra.program.model.listing.Program) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

