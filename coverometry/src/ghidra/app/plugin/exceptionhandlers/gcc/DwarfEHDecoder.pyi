import ghidra.app.plugin.exceptionhandlers.gcc
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang


class DwarfEHDecoder(object):
    """
    Decodes a sequence of program bytes to Ghidra addressing types.
    """









    def decode(self, context: ghidra.app.plugin.exceptionhandlers.gcc.DwarfDecodeContext) -> long:
        """
        Decodes an integer value which is indicated by the context.
        @param context Stores program location and decode parameters
        @return the value
        @throws MemoryAccessException if the data can't be read
        """
        ...

    def decodeAddress(self, context: ghidra.app.plugin.exceptionhandlers.gcc.DwarfDecodeContext) -> ghidra.program.model.address.Address:
        """
        Decodes the address which is indicated by the context.
        @param context Stores program location and decode parameters
        @return the address
        @throws MemoryAccessException if the data can't be read
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataApplicationMode(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDataApplicationMode:
        """
        Gets the data application mode.
        @return the data application mode
        """
        ...

    def getDataFormat(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDataDecodeFormat:
        """
        Gets the exception handling data decoding format.
        @return the data decoding format
        """
        ...

    def getDataType(self, program: ghidra.program.model.listing.Program) -> ghidra.program.model.data.DataType:
        """
        Gets this decoder's encoded data type.
        @param program the program containing the data to be decoded.
        @return the data type.
        """
        ...

    def getDecodeSize(self, program: ghidra.program.model.listing.Program) -> int:
        """
        Gets the size of the encoded data.
        @param program the program containing the data to be decoded.
        @return the size of the encoded data
        """
        ...

    def hashCode(self) -> int: ...

    def isSigned(self) -> bool:
        """
        Whether or not this decoder is for decoding signed or unsigned data.
        @return true if the decoder is for signed data. false for unsigned
        """
        ...

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
    def dataApplicationMode(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDataApplicationMode: ...

    @property
    def dataFormat(self) -> ghidra.app.plugin.exceptionhandlers.gcc.DwarfEHDataDecodeFormat: ...

    @property
    def signed(self) -> bool: ...