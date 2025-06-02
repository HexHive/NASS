import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import java.lang


class DwarfDecodeContext(object):
    """
    Organizational class to record vital data used by a DwarfEHDecoder.
    """





    @overload
    def __init__(self, buffer: ghidra.program.model.mem.MemBuffer, length: int):
        """
        Constructs a Dwarf decode context.
        @param buffer the memory buffer which provides the program and address of the encoded data
        @param length the length of the encoded data
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.listing.Program, readAddr: ghidra.program.model.address.Address):
        """
        Constructs a Dwarf decode context.
        @param program the program containing the encoded data
        @param readAddr the address of the encoded data
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.listing.Program, readAddr: ghidra.program.model.address.Address, entryPoint: ghidra.program.model.address.Address):
        """
        Constructs a Dwarf decode context.
        @param program the program containing the encoded data
        @param readAddr the address of the encoded data
        @param entryPoint the associated function's entry point
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.listing.Program, readAddr: ghidra.program.model.address.Address, function: ghidra.program.model.listing.Function):
        """
        Constructs a Dwarf decode context.
        @param program the program containing the encoded data
        @param readAddr the address of the encoded data
        @param function the associated function
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.listing.Program, readAddr: ghidra.program.model.address.Address, ehBlock: ghidra.program.model.mem.MemoryBlock):
        """
        Constructs a Dwarf decode context.
        @param program the program containing the encoded data
        @param readAddr the address of the encoded data
        @param ehBlock the exception handling memory block
        """
        ...

    @overload
    def __init__(self, buf: ghidra.program.model.mem.MemBuffer, length: int, ehBlock: ghidra.program.model.mem.MemoryBlock, entryPoint: ghidra.program.model.address.Address):
        """
        Constructs a Dwarf decode context.
        @param buf the memory buffer which provides the program and address of the encoded data
        @param length the length of the encoded data
        @param ehBlock the exception handling memory block
        @param entryPoint the function entry point
        """
        ...

    @overload
    def __init__(self, program: ghidra.program.model.listing.Program, readAddr: ghidra.program.model.address.Address, ehBlock: ghidra.program.model.mem.MemoryBlock, entryPoint: ghidra.program.model.address.Address):
        """
        Constructs a Dwarf decode context.
        @param program the program containing the encoded data
        @param readAddr the address of the encoded data
        @param ehBlock the exception handling memory block
        @param entryPoint the associated function's entry point
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Gets the min address of the encoded data.
        @return the address
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDecodedValue(self) -> object:
        """
        Gets the decoded value that is at the address.
        @return the decoded value
        """
        ...

    def getEhBlock(self) -> ghidra.program.model.mem.MemoryBlock:
        """
        Gets the exception handling memory block with this dwarf encoded data.
        @return the memory block
        """
        ...

    def getEncodedLength(self) -> int:
        """
        Gets the length of the encoded data that is at the address.
        @return the encoded data's length
        """
        ...

    def getFunctionEntryPoint(self) -> ghidra.program.model.address.Address:
        """
        Gets the associated function's entry point.
        @return the entry point address
        """
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Gets the program containing the encoded data.
        @return the program
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setDecodedValue(self, value: object, encodedLength: int) -> None:
        """
        Set the value and value-length after decode
        @param value The integer-value having been decoded
        @param encodedLength The length of the encoded integer-value
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
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def decodedValue(self) -> object: ...

    @property
    def ehBlock(self) -> ghidra.program.model.mem.MemoryBlock: ...

    @property
    def encodedLength(self) -> int: ...

    @property
    def functionEntryPoint(self) -> ghidra.program.model.address.Address: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...