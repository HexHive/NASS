from typing import List
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable
import ghidra.program.model.address
import java.lang


class LSDAActionTable(object):
    """
    Defines the follow-on behavior of how to handle an exception in the context
     of the exceptions' C++ type.
    """





    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Constructor for an action table.
         <br>Note: The <code>create(Address)</code> method must be called after constructing an 
         LSDAActionTable to associate it with an address before any of its "get..." methods are called.
        @param monitor task monitor to see if the user has cancelled analysis.
        @param program the program containing the action table.
        @param region the region or section of the program containing the action table.
        """
        ...



    def create(self, address: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address) -> None:
        """
        Create an LSDA Action Table from the bytes at <code>address</code>.
         <br>Note: This method must get called before any of the "get..." methods.
        @param address the start (minimum address) of this action table.
        @param maxAddress the end (maximum address) of this action table.
        @throws MemoryAccessException
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getActionRecord(self, actionIndex: int) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionRecord:
        """
        Gets the action record from the table by its index.
        @param actionIndex indicates which action record (0 based) to get from the table.
        @return the action record or null if the index is invalid or an address hasn't been 
         established for this table yet.
        """
        ...

    def getActionRecordAtOffset(self, actionOffset: int) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionRecord:
        """
        Gets the action record from the table for the indicated offset.
        @param actionOffset the byte offset into the table for the desired record
        @return the action record for the specified offset or null
        """
        ...

    def getActionRecords(self) -> List[ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionRecord]:
        """
        Gets all of the action records in this action table.
        @return the action records in this table or empty if no address has been established for 
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
    def actionRecords(self) -> List[object]: ...