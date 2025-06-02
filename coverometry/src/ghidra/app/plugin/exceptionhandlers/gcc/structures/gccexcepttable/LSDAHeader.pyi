import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.program.model.address
import java.lang


class LSDAHeader(ghidra.app.plugin.exceptionhandlers.gcc.GccAnalysisClass):
    """
    Defines the bounds of exception unwinding support, within a function, 
     and unwind procedures.
     * lpStartAddr is the program address where support begins. This value is 
       encoded according to lpStartEncoding.
     * ttypeAddr is the location-relative program address, encoded per 
       ttypeEncoding, of the associated C++ types table (types of thrown values).
    """





    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program, region: ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor):
        """
        Constructor for the LSDA header which indicates encoding for the LSDA tables.
         <br>Note: The <code>create(Address)</code> method must be called after constructing an 
         LSDAHeader to associate it with an address before any of its "get..." methods are called.
        @param monitor task monitor to see if the user has cancelled analysis.
        @param program the program containing this header.
        @param region the region of the program associated with this header.
        """
        ...



    def create(self, addr: ghidra.program.model.address.Address) -> None:
        """
        Create a LSDA Header from the bytes at <code>addr</code>.
         <br>Note: This method must get called before any of the "get..." methods.
        @param addr the start (minimum address) of this LSDA header.
        @throws MemoryAccessException if memory for the header couldn't be read.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getBody(self) -> ghidra.program.model.address.AddressRange:
        """
        Gets the address range containing the LSDA header.
        @return the address range of the header
        """
        ...

    def getCallSiteTableEncoding(self) -> int:
        """
        Gets the dwarf encoding used for the call site table.
        @return the encoding value
        """
        ...

    def getCallSiteTableHeaderSize(self) -> int:
        """
        Get the size of the header in the call site table.
        @return the header size
        """
        ...

    def getCallSiteTableLength(self) -> int:
        """
        Gets the length of the call site table.
        @return the table length
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getHeaderSize(self) -> long:
        """
        Gets the size of this LSDA header.
        @return the header size
        """
        ...

    def getLPStartAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the landing pad start address.
        @return the LP start address
        """
        ...

    def getLPStartEncoding(self) -> int:
        """
        Gets the indicator of the encoding used for the landing pad start.
        @return the LP start encoding
        """
        ...

    def getNextAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the next address indicating the address after this LSDA header.
        @return the next address after this LSDA header or null if this LSDA header hasn't been 
         created at any address yet.
        """
        ...

    def getTTypeBaseAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the base address of the type table. The base address is the last byte (maximum address) 
         of the type table. The type table is ordered in reverse.
        @return the type table's base address or <code>Address.NO_ADDRESS</code>
        """
        ...

    def getTTypeEncoding(self) -> int:
        """
        Gets the encoding used for the type table.
        @return the value indicating the type table's encoding
        """
        ...

    def getTTypeOffset(self) -> int:
        """
        The offset from the type offset field to get to the base address of the type table.
        @return the type table offset
        """
        ...

    def hasTypeTable(self) -> bool:
        """
        Determines if this LSDA has a type table.
        @return true if there is a type table
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
    def LPStartAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def LPStartEncoding(self) -> int: ...

    @property
    def TTypeBaseAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def TTypeEncoding(self) -> int: ...

    @property
    def TTypeOffset(self) -> int: ...

    @property
    def body(self) -> ghidra.program.model.address.AddressRange: ...

    @property
    def callSiteTableEncoding(self) -> int: ...

    @property
    def callSiteTableHeaderSize(self) -> int: ...

    @property
    def callSiteTableLength(self) -> int: ...

    @property
    def headerSize(self) -> long: ...

    @property
    def nextAddress(self) -> ghidra.program.model.address.Address: ...