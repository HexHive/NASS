from typing import List
import ghidra.app.util.bin
import ghidra.program.model.listing
import ghidra.util.task
import java.io
import java.lang


class DWARFSectionProvider(java.io.Closeable, object):
    """
    A DWARFSectionProvider is responsible for allowing access to DWARF section data of
     a Ghidra program.
 
     Implementors of this interface need to be registered in 
     DWARFSectionProviderFactory#sectionProviderFactoryFuncs and should implement the 
     static method:
 
     public static DWARFSectionProvider createSectionProviderFor(Program program, TaskMonitor monitor)
 
     that is called via a java Function wrapper.
 
     DWARFSectionProvider instances are responsible for ByteProvider#close() 
     any ByteProvider that has been returned via 
     #getSectionAsByteProvider(String, TaskMonitor) when the section provider instance is 
     itself closed.
    """









    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getSectionAsByteProvider(self, sectionName: unicode, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a ByteProvider for the specified section.
        @param sectionName name of the section
        @param monitor {@link TaskMonitor} to use when performing long operations
        @return ByteProvider, which will be closed by the section provider when itself is closed
        @throws IOException if error
        """
        ...

    def hasSection(self, sectionNames: List[unicode]) -> bool:
        """
        Returns true if the specified section names are present.
        @param sectionNames list of section names to test
        @return true if all are present, false if not present
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def updateProgramInfo(self, program: ghidra.program.model.listing.Program) -> None:
        """
        Decorate the specified program with any information that is unique to this section provider.
        @param program {@link Program} with an active transaction
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

