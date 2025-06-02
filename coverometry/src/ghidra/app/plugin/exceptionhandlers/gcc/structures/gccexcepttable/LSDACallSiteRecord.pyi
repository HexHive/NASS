import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.program.model.address
import java.lang


class LSDACallSiteRecord(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    Defines the bounds of a try-catch region.
    """





    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Constructor for a call site record.
         <br>Note: The <code>create(Address)</code> method must be called after constructing an 
         LSDACallSiteRecord to associate it with an address before any of its "get..." methods are 
         called.
        @param monitor task monitor to see if the user has cancelled analysis.
        @param program the program containing the call site record.
        @param region the region of the program associated with the call site record.
        """
        ...



    def create(self, addr: ghidra.program.model.address.Address, decoder: ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder) -> None:
        """
        Creates data for a call site record at the indicated address and creates a comment to 
         identify it as a call site record.
         <br>Note: This method must get called before any of the "get..." methods.
        @param addr the start (minimum address) of this call site record.
        @param decoder decodes dwarf encoded information within the LSDA
        @throws MemoryAccessException if memory couldn't be accessed for the call site record
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getActionOffset(self) -> int:
        """
        Get the offset into the action table for the first action record to be caught.
        @return the offset into the action table
        """
        ...

    def getCallSite(self) -> ghidra.program.model.address.AddressRange:
        """
        Get the call site addresses which make up the <code>try</code>.
        @return the address range of the call site
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getLandingPad(self) -> ghidra.program.model.address.Address:
        """
        Get the landing pad address which indicates the <code>catch</code> for this call site.
        @return the landing pad address of the catch.
        """
        ...

    def getLandingPadOffset(self) -> long:
        """
        Gets the offset of the landing pad address from the landing pad start.
        @return the landing pad offset
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
    def actionOffset(self) -> int: ...

    @property
    def callSite(self) -> ghidra.program.model.address.AddressRange: ...

    @property
    def landingPad(self) -> ghidra.program.model.address.Address: ...

    @property
    def landingPadOffset(self) -> long: ...