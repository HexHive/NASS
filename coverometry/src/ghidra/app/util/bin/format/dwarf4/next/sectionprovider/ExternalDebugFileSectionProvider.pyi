from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider
import ghidra.formats.gfilesystem
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class ExternalDebugFileSectionProvider(ghidra.app.util.bin.format.dwarf4.next.sectionprovider.BaseSectionProvider):
    """
    A DWARFSectionProvider that reads .debug_info (and friends) sections from an external
     ELF file that is referenced in the original ELF file's build-id or debuglink sections.
 
     Creates a pinning reference from the temporary external ELF debug file to this SectionProvider
     instance using the program's Program#addConsumer(Object), and then releases the
     consumer when this instance is closed, allowing the temporary Program to be destroyed.
    """

    PROGRAM_INFO_DWARF_EXTERNAL_DEBUG_FILE: unicode = u'DWARF External Debug File'







    def close(self) -> None: ...

    @staticmethod
    def createExternalSectionProviderFor(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DWARFSectionProvider: ...

    @staticmethod
    def createSectionProviderFor(program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.format.dwarf4.next.sectionprovider.BaseSectionProvider: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getExternalDebugFileLocation(program: ghidra.program.model.listing.Program) -> ghidra.formats.gfilesystem.FSRL:
        """
        Returns the previously saved value of the external debug file location from the program's
         metadata.
        @param program DWARF that previously was analyzed
        @return FSRL of external debug file, or null if missing or corrupted value
        """
        ...

    def getSectionAsByteProvider(self, sectionName: unicode, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider: ...

    def hasSection(self, sectionNames: List[unicode]) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def updateProgramInfo(self, program: ghidra.program.model.listing.Program) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

