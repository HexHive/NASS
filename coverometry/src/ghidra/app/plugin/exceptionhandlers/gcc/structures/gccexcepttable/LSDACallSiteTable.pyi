from typing import List
import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable
import ghidra.program.model.address
import java.lang


class LSDACallSiteTable(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    Defines the specific program regions that may throw an exception within the 
     context of the LSDA.
    """





    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Constructor for a call site table.
         <br>Note: The <code>create(Address)</code> method must be called after constructing an 
         LSDACallSiteTable to associate it with an address before any of its "get..." methods are called.
        @param monitor task monitor to see if the user has cancelled analysis.
        @param program the program containing the call site table.
        @param region the region of the program associated with the call site table.
        """
        ...



    def create(self, addr: ghidra.program.model.address.Address) -> None:
        """
        Create a LSDA Call Site Table from the bytes at <code>addr</code>.
         <br>Note: This method must get called before any of the "get..." methods.
        @param addr the start (minimum address) of this call site table.
        @throws MemoryAccessException if memory couldn't be accessed for the call site table
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getCallSiteRecords(self) -> List[ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDACallSiteRecord]:
        """
        Gets all of the call site records in this table.
        @return the call site records in this table or empty if no address has been established for 
         this table.
        """
        ...

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

    @property
    def callSiteRecords(self) -> List[object]: ...