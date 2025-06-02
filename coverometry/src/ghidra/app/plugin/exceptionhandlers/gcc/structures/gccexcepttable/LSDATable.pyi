import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable
import ghidra.program.model.address
import java.lang


class LSDATable(object):
    """
    The Language Specific Data Area (LSDA) serves as a reference to the runtime for how to 
     respond to an exception. Each function that handles an exception (that is, has a 'catch' 
     block) has an LSDA, and each exception-prone fragment has a record within the LSDA.
     The runtime will walk up the call stack as part of the Unwind routines, asking the LSDA 
     if a function knows how to handle the thrown exception;the default handler typically 
     terminates the program. 
 
     Unwind uses the personality function and the LSDA -- the return value tells Unwind whether 
     the function can handle the exception or not.
 
       The LSDA is comprised of:
   
       A header that describes the bounds of exception handling support and encoding
         modes for values found later in the LSDA table
       A call site table that describes each location a 'throws' occurs and where
         a corresponding catch block resides, and the actions to take.
       An action table, that describes what the runtime needs to do during unwind
   
   
     The structures modeled here are described in detail in the C++ ABI.
    """





    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program):
        """
        Constructor for an LSDA exception table.
         <br>Note: The <code>create(Address, DwarfEHDecoder, RegionDescriptor)</code> method must be 
         called after constructing an LSDATable to associate it with an address before any of 
         its "get..." methods are called.
        @param monitor task monitor to see if the user has cancelled analysis
        @param program the program containing the table
        """
        ...



    def create(self, tableAddr: ghidra.program.model.address.Address, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor) -> None:
        """
        Create a LSDA Table from the bytes at <code>addr</code>. Parses the header, call site table,
         action table, and type table.
         <br>Note: This method must get called before any of the "get..." methods.
        @param tableAddr the start (minimum address) of this LSDA table.
        @param region the region of the program associated with this table
        @throws MemoryAccessException if memory couldn't be accessed for the LSDA table
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getActionTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable:
        """
        @return the action table for this LSDA
        """
        ...

    def getCallSiteTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDACallSiteTable:
        """
        @return the call site table for this LSDA
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getTypeTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATypeTable:
        """
        @return the type table for this LSDA
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
    def actionTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable: ...

    @property
    def callSiteTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDACallSiteTable: ...

    @property
    def typeTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATypeTable: ...