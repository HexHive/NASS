import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable
import ghidra.program.model.address
import java.lang


class LSDAActionRecord(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    A record that associates the type info with a catch action.
    """

    NO_ACTION: long = 0x0L



    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor, lsdaActionTable: ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable):
        """
        Constructor for an action record.
         <br>Note: The <code>create(Address)</code> method must be called after constructing an 
         LSDAActionRecord to associate it with an address before any of its "get..." methods are called.
        @param monitor task monitor to see if the user has cancelled analysis.
        @param program the program containing the action record.
        @param region the region of the program associated with the action record.
        @param lsdaActionTable the action table containing the action record.
        """
        ...



    def create(self, address: ghidra.program.model.address.Address) -> None:
        """
        Creates data for an action record at the indicated address and creates a comment to identify
         it as an action record.
         <br>Note: This method must get called before any of the "get..." methods.
        @param address the start (minimum address) of this action record.
        @throws MemoryAccessException
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getActionTypeFilter(self) -> int:
        """
        Gets the filter value indicating which type is associated with this action record.
        @return the value for this action's type.
        """
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the base address (minimum address) indicating the start of this action record.
        @return the address of this action record or null if this action record hasn't been 
         created at any address yet.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getNextAction(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionRecord:
        """
        Gets the record for the next action that the catch should fall to if the type isn't 
         the one for this action.
        @return the next action's record or null if there isn't another specific type of 
         exception for this try.
        """
        ...

    def getNextActionAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the base address of the next action record to consider in the action table.
        @return the address of the next action record or null.
        """
        ...

    def getNextAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the next address indicating the address after this action record.
        @return the next address after this action record or null if this action record hasn't been 
         created at any address yet.
        """
        ...

    def getSize(self) -> int:
        """
        Gets the size of the action record or 0 if this action record hasn't been created at any 
         address yet.
        @return the size of the action record or 0;
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
    def actionTypeFilter(self) -> int: ...

    @property
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def nextAction(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionRecord: ...

    @property
    def nextActionAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def nextAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def size(self) -> int: ...