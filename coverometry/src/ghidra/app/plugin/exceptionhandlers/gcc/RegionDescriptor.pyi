import ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable
import ghidra.program.model.address
import ghidra.program.model.mem
import java.lang


class RegionDescriptor(object):
    """
    RegionDescriptor holds information about a call frame.
    """





    def __init__(self, ehblock: ghidra.program.model.mem.MemoryBlock):
        """
        Constructor for a region descriptor.
        @param ehblock the exception handling memory block for the region to be described.
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getActionTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable:
        """
        Gets the action table for this region's frame.
        @return the action table or null if it hasn't been set for this region
        """
        ...

    def getCallSiteTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDACallSiteTable:
        """
        Gets the call site table for this region's frame.
        @return the call site table
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getEHMemoryBlock(self) -> ghidra.program.model.mem.MemoryBlock:
        """
        Gets the exception handling memory block associated with this region.
        @return the memory block
        """
        ...

    def getFrameDescriptorEntry(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry:
        """
        Gets the FDE associated with this region.
        @return the FDE
        """
        ...

    def getLSDAAddress(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the address of the start of the LSDA.
        @return the LSDA address.
        """
        ...

    def getLSDATable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable:
        """
        Gets the LSDA table for this frame region.
        @return the LSDA table
        """
        ...

    def getRange(self) -> ghidra.program.model.address.AddressRange:
        """
        Gets the address range of the IP (instructions) for this region.
        @return the instruction addresses
        """
        ...

    def getRangeSize(self) -> long:
        """
        Gets the size of the address range for the IP.
        @return the IP address range size
        """
        ...

    def getRangeStart(self) -> ghidra.program.model.address.Address:
        """
        Gets the start (minimum address) of the IP range for this region.
        @return the IP range start address
        """
        ...

    def getTypeTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATypeTable:
        """
        Gets the type table for this region's frame.
        @return the LSDA type table or null if it hasn't been set for this region
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setFrameDescriptorEntry(self, frameDescriptionEntry: ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry) -> None:
        """
        Sets the FDE associated with the region.
        @param frameDescriptionEntry the FDE
        """
        ...

    def setIPRange(self, range: ghidra.program.model.address.AddressRange) -> None:
        """
        Sets the address range of the IP (instructions) for this region.
        @param range the address range to associate with this region.
        """
        ...

    def setLSDAAddress(self, addr: ghidra.program.model.address.Address) -> None:
        """
        Sets the address of the start of the LSDA.
        @param addr the LSDA address.
        """
        ...

    def setLSDATable(self, lsdaTable: ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable) -> None:
        """
        Sets the LSDA table for this frame region.
        @param lsdaTable the LSDA table
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def EHMemoryBlock(self) -> ghidra.program.model.mem.MemoryBlock: ...

    @property
    def IPRange(self) -> None: ...  # No getter available.

    @IPRange.setter
    def IPRange(self, value: ghidra.program.model.address.AddressRange) -> None: ...

    @property
    def LSDAAddress(self) -> None: ...  # No getter available.

    @LSDAAddress.setter
    def LSDAAddress(self, value: ghidra.program.model.address.Address) -> None: ...

    @property
    def LSDATable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable: ...

    @LSDATable.setter
    def LSDATable(self, value: ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable) -> None: ...

    @property
    def actionTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable: ...

    @property
    def callSiteTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDACallSiteTable: ...

    @property
    def frameDescriptorEntry(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry: ...

    @frameDescriptorEntry.setter
    def frameDescriptorEntry(self, value: ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame.FrameDescriptionEntry) -> None: ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange: ...

    @property
    def rangeSize(self) -> long: ...

    @property
    def rangeStart(self) -> ghidra.program.model.address.Address: ...

    @property
    def typeTable(self) -> ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATypeTable: ...