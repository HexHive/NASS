import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.program.model.address
import java.lang


class LSDATypeTable(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    Stores addresses of __type_info structures for thrown values. Used by the Unwind routines
     to determine if a given catch block appropriately handles a given exception-of-type.
    """





    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Constructor for a table of references to types that are associated with catch actions.
         <br>Note: The <code>create(Address, Address)</code> method must be called after constructing 
         an LSDATypeTable to associate it with an address before any of its "get..." methods 
         are called.
        @param monitor task monitor to see if the user has cancelled analysis.
        @param program the program containing the type table.
        @param region the region of the program associated with this type table.
        """
        ...



    def create(self, bottom: ghidra.program.model.address.Address, top: ghidra.program.model.address.Address) -> None:
        """
        Create a LSDA Type Table from the bytes between <code>bottom</code> and <code>top</code>. 
         This table is built from bottom-to-top.
         <br>Note: This method must get called before any of the "get..." methods.
        @param bottom the bottom address of the type table
        @param top the top address of the type table
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getNextAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the address after this type table.
        @return the next address after this type table or null if this type table hasn't been 
         created at any address yet.
        """
        ...

    def getTypeInfoAddress(self, index: int) -> ghidra.program.model.address.Address:
        """
        Gets the address of the type information from the reference record at the specified index in 
         the table.
        @param index the index (1-based) of the type info table record.
        @return the address of the type info.
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
    def nextAddress(self) -> ghidra.program.model.address.Address: ...