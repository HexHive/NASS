import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class AbstractDwarfEHDecoder(object, ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDecoder):
    """
    Extended by each of the various Dwarf exception handling decoders. Provides basic types and 
     methods for maintaining and retrieving information specific to that decoder.
    """









    def decode(self, context: ghidra.app.plugin.exceptionhandlers.gcc.DwarfDecodeContext) -> long:
        """
        Get the DWARF-encoded integer value as stored by the context
        @param context Stores program location and decode parameters
        @return the integer value
        @throws MemoryAccessException if the data can't be read
        """
        ...

    def decodeAddress(self, context: ghidra.app.plugin.exceptionhandlers.gcc.DwarfDecodeContext) -> ghidra.program.model.address.Address:
        """
        Get the DWARF-encoded address value as stored by the context
        @param context Stores program location and decode parameters
        @return the address
        @throws MemoryAccessException if the data can't be read
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataApplicationMode(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDataApplicationMode: ...

    def getDataFormat(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDataDecodeFormat: ...

    def getDataType(self, __a0: ghidra.program.model.listing.Program) -> ghidra.program.model.data.DataType: ...

    def getDecodeSize(self, __a0: ghidra.program.model.listing.Program) -> int: ...

    def hashCode(self) -> int: ...

    def isSigned(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

