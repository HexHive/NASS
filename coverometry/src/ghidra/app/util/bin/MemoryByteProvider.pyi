from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import java.io
import java.lang


class MemoryByteProvider(object, ghidra.app.util.bin.ByteProvider):
    """
    A ByteProvider implementation based on Memory.
 
     The bytes returned by this provider are indexed relative to the 
     supplied to the constructor, and are limited to MemoryBlock of the
     same address space.
 
     Warnings:
 
     Using this ByteProvider with memory block/address spaces that are not simple "ram" initialized 
     memory blocks is fraught with peril.
 
     Addresses and address spaces can use all 64 bits of a  as an offset, which 
     causes a problem when trying to express the correct #length() of this ByteProvider as
     a long. (this is why address ranges deal with inclusive end values instead of exclusive).
 
     	The return value of #length() is constrained to a max of Long.MAX_VALUE
     	#isValidIndex(long) treats its argument as an unsigned int64, and works
     	for the entire address space range.
 
 
     Not all byte provider index locations between 0 and #length() will be valid
     (because gaps between memory blocks), and may generate exceptions when those locations are read.
 
      To avoid this situation, the caller will need to use information from the program's Memory
      manager to align reads to valid locations.
 
    """

    EMPTY_BYTEPROVIDER: ghidra.app.util.bin.ByteProvider = ghidra.app.util.bin.EmptyByteProvider@5a458540



    @overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, baseAddress: ghidra.program.model.address.Address):
        """
        Constructs a new {@link MemoryByteProvider} relative to the specified base address,
         containing the address range to the highest address in the same address space currently
         found in the memory map.
        @param memory the {@link Memory}
        @param baseAddress the base address
        """
        ...

    @overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, space: ghidra.program.model.address.AddressSpace):
        """
        Constructs a new {@link MemoryByteProvider} for a specific {@link AddressSpace}.  Bytes 
         will be provided relative to the minimum address (typically 0) in the space, and ranges 
         to the highest address in the same address space currently found in the memory map.
         <p>
        @param memory the {@link Memory}
        @param space the {@link AddressSpace}
        """
        ...

    @overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, baseAddress: ghidra.program.model.address.Address, firstBlockOnly: bool):
        """
        Constructs a new {@link MemoryByteProvider} relative to the specified base address,
         containing the address range to the end of the first memory block, or the highest address
         in the same address space, currently found in the memory map.
        @param memory the {@link Memory}
        @param baseAddress the base address
        @param firstBlockOnly boolean flag, if true, only the first memory block will be accessible,
         if false, all memory blocks of the address space will be accessible
        """
        ...

    @overload
    def __init__(self, memory: ghidra.program.model.mem.Memory, baseAddress: ghidra.program.model.address.Address, maxAddress: ghidra.program.model.address.Address):
        """
        Constructs a new {@link MemoryByteProvider} relative to the specified base address, with
         the specified length.
        @param memory the {@link Memory}
        @param baseAddress the base address
        @param maxAddress the highest address accessible by this provider (inclusive), or null
         if there is no memory
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

    @property
    def FSRL(self) -> ghidra.formats.gfilesystem.FSRL: ...

    @property
    def absolutePath(self) -> unicode: ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSetView: ...

    @property
    def empty(self) -> bool: ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def file(self) -> java.io.File: ...

    @property
    def name(self) -> unicode: ...

    @property
    def startAddress(self) -> ghidra.program.model.address.Address: ...