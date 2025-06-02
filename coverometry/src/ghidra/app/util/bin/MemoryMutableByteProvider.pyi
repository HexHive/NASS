from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import java.io
import java.lang


class MemoryMutableByteProvider(ghidra.app.util.bin.MemoryByteProvider, ghidra.app.util.bin.MutableByteProvider):
    """
    A Byte Provider implementation based on Memory.
    """





    @overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, baseAddress: ghidra.program.model.address.Address):
        """
        Constructs a new provider relative to the base address.
        @param memory the memory
        @param baseAddress the relative base address
        """
        ...

    @overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, space: ghidra.program.model.address.AddressSpace):
        """
        Constructs a new provider for a specific address space.
        @param memory the memory
        """
        ...



    def close(self) -> None: ...

    @staticmethod
    def createDefaultAddressSpaceByteProvider(program: ghidra.program.model.listing.Program, firstBlockOnly: bool) -> ghidra.app.util.bin.MemoryByteProvider:
        """
        Create a {@link ByteProvider} that starts at the beginning (e.g. 0) of the specified 
         {@link Program program's} default address space memory, containing either the first memory 
         block, or all memory blocks (of the same address space).
        @param program {@link Program} to read
        @param firstBlockOnly boolean flag, if true, only the first memory block will be accessible
         via the returned provider, if false, all memory blocks of the address space will be accessible
        @return new {@link MemoryByteProvider}, starting at program's minAddress
        """
        ...

    @staticmethod
    def createMemoryBlockByteProvider(memory: ghidra.program.model.mem.Memory, block: ghidra.program.model.mem.MemoryBlock) -> ghidra.app.util.bin.MemoryByteProvider:
        """
        Create a {@link ByteProvider} that is limited to the specified {@link MemoryBlock}.
        @param memory {@link Memory} of the program
        @param block {@link MemoryBlock} to read from
        @return new {@link ByteProvider} that contains the bytes of the specified MemoryBlock
        """
        ...

    @staticmethod
    def createProgramHeaderByteProvider(program: ghidra.program.model.listing.Program, firstBlockOnly: bool) -> ghidra.app.util.bin.MemoryByteProvider:
        """
        Create a {@link ByteProvider} that starts at the beginning of the specified 
         {@link Program program's} memory, containing either just the first 
         memory block, or all memory blocks (of the same address space).
        @param program {@link Program} to read
        @param firstBlockOnly boolean flag, if true, only the first memory block will be accessible
         via the returned provider, if false, all memory blocks of the address space will be accessible
        @return new {@link MemoryByteProvider}, starting at program's minAddress
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAbsolutePath(self) -> unicode: ...

    def getAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the address range of the bytes of this provider.
        @return address range of first byte to last byte of this provider
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the last byte of this provider.
        @return address of the last byte returned by this provider
        """
        ...

    def getFSRL(self) -> ghidra.formats.gfilesystem.FSRL: ...

    def getFile(self) -> java.io.File: ...

    def getInputStream(self, __a0: long) -> java.io.InputStream: ...

    def getName(self) -> unicode: ...

    def getStartAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the first byte of this provider.
        @return address of the first byte returned by this provider (at index 0)
        """
        ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    def isValidIndex(self, index: long) -> bool: ...

    def length(self) -> long: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readByte(self, index: long) -> int: ...

    def readBytes(self, index: long, length: long) -> List[int]: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeByte(self, index: long, value: int) -> None: ...

    def writeBytes(self, index: long, values: List[int]) -> None: ...

