from typing import Iterator
from typing import List
import ghidra.program.database.mem
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.util.task
import java.io
import java.lang
import java.util
import java.util.function


class StubMemory(ghidra.program.model.address.AddressSet, ghidra.program.model.mem.Memory):
    """
    MemoryStub can be extended for use by tests. It throws an UnsupportedOperationException
     for all methods in the Memory interface. Any method that is needed for your test can then
     be overridden so it can provide its own test implementation and return value.
    """





    @overload
    def __init__(self): ...

    @overload
    def __init__(self, bytes: List[int]): ...

    def __iter__(self): ...

    @overload
    def add(self, address: ghidra.program.model.address.Address) -> None:
        """
        Adds the given address to this set.
        @param address the address to add
        """
        ...

    @overload
    def add(self, range: ghidra.program.model.address.AddressRange) -> None:
        """
        Add an address range to this set.
        @param range the range to add.
        """
        ...

    @overload
    def add(self, addressSet: ghidra.program.model.address.AddressSetView) -> None:
        """
        Add all addresses of the given AddressSet to this set.
        @param addressSet set of addresses to add.
        """
        ...

    @overload
    def add(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> None:
        """
        Adds the range to this set
        @param start the start address of the range to add
        @param end the end address of the range to add
        """
        ...

    @overload
    def addRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> None:
        """
        Adds the range to this set
        @param start the start address of the range to add
        @param end the end address of the range to add
        @throws IllegalArgumentException if the start and end addresses are in different spaces.  To
         avoid this, use the constructor  {@link #addRange(Program, Address, Address)}
        """
        ...

    @overload
    def addRange(self, program: ghidra.program.model.listing.Program, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> None:
        """
        Adds a range of addresses to this set.
        @param program program whose AddressFactory is used to resolve address ranges that span
         multiple address spaces.
        @param start the start address of the range to add
        @param end the end address of the range to add
        """
        ...

    def clear(self) -> None:
        """
        Removes all addresses from the set.
        """
        ...

    @overload
    def contains(self, address: ghidra.program.model.address.Address) -> bool: ...

    @overload
    def contains(self, addrSet: ghidra.program.model.address.AddressSetView) -> bool: ...

    @overload
    def contains(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool: ...

    def convertToInitialized(self, uninitializedBlock: ghidra.program.model.mem.MemoryBlock, initialValue: int) -> ghidra.program.model.mem.MemoryBlock: ...

    def convertToUninitialized(self, initializedBlock: ghidra.program.model.mem.MemoryBlock) -> ghidra.program.model.mem.MemoryBlock: ...

    def createBitMappedBlock(self, name: unicode, start: ghidra.program.model.address.Address, mappedAddress: ghidra.program.model.address.Address, length: long, overlay: bool) -> ghidra.program.model.mem.MemoryBlock: ...

    def createBlock(self, block: ghidra.program.model.mem.MemoryBlock, name: unicode, start: ghidra.program.model.address.Address, length: long) -> ghidra.program.model.mem.MemoryBlock: ...

    @overload
    def createByteMappedBlock(self, __a0: unicode, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.address.Address, __a3: long, __a4: bool) -> ghidra.program.model.mem.MemoryBlock: ...

    @overload
    def createByteMappedBlock(self, name: unicode, start: ghidra.program.model.address.Address, mappedAddress: ghidra.program.model.address.Address, length: long, byteMappingScheme: ghidra.program.database.mem.ByteMappingScheme, overlay: bool) -> ghidra.program.model.mem.MemoryBlock: ...

    def createFileBytes(self, filename: unicode, offset: long, size: long, is_: java.io.InputStream, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.database.mem.FileBytes: ...

    @overload
    def createInitializedBlock(self, name: unicode, start: ghidra.program.model.address.Address, fileBytes: ghidra.program.database.mem.FileBytes, offset: long, size: long, overlay: bool) -> ghidra.program.model.mem.MemoryBlock: ...

    @overload
    def createInitializedBlock(self, name: unicode, start: ghidra.program.model.address.Address, is_: java.io.InputStream, length: long, monitor: ghidra.util.task.TaskMonitor, overlay: bool) -> ghidra.program.model.mem.MemoryBlock: ...

    @overload
    def createInitializedBlock(self, name: unicode, start: ghidra.program.model.address.Address, size: long, initialValue: int, monitor: ghidra.util.task.TaskMonitor, overlay: bool) -> ghidra.program.model.mem.MemoryBlock: ...

    def createUninitializedBlock(self, name: unicode, start: ghidra.program.model.address.Address, size: long, overlay: bool) -> ghidra.program.model.mem.MemoryBlock: ...

    @overload
    def delete(self, range: ghidra.program.model.address.AddressRange) -> None:
        """
        Deletes an address range from this set.
        @param range AddressRange to remove from this set
        """
        ...

    @overload
    def delete(self, addressSet: ghidra.program.model.address.AddressSetView) -> None:
        """
        Delete all addresses in the given AddressSet from this set.
        @param addressSet set of addresses to remove from this set.
        """
        ...

    @overload
    def delete(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> None:
        """
        Deletes a range of addresses from this set
        @param start the starting address of the range to be removed
        @param end the ending address of the range to be removed (inclusive)
        """
        ...

    def deleteFileBytes(self, descriptor: ghidra.program.database.mem.FileBytes) -> bool: ...

    def deleteFromMin(self, toAddr: ghidra.program.model.address.Address) -> None:
        """
        Delete all addresses from the minimum address in the set up to and including toAddr.
         Addresses less-than-or-equal to specified 
         address based upon {@link Address} comparison.
        @param toAddr only addresses greater than toAddr will be left in the set.
        """
        ...

    def deleteRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> None:
        """
        Deletes a range of addresses from this set
        @param start the starting address of the range to be removed
        @param end the ending address of the range to be removed
        """
        ...

    def deleteToMax(self, fromAddr: ghidra.program.model.address.Address) -> None:
        """
        Delete all addresses starting at the fromAddr to the maximum address in the set.
         Addresses greater-than-or-equal to specified 
         address based upon {@link Address} comparison.
        @param fromAddr only addresses less than fromAddr will be left in the set.
        """
        ...

    def equals(self, obj: object) -> bool: ...

    @overload
    def findBytes(self, addr: ghidra.program.model.address.Address, bytes: List[int], masks: List[int], forward: bool, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address: ...

    @overload
    def findBytes(self, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address, bytes: List[int], masks: List[int], forward: bool, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address: ...

    def findFirstAddressInCommon(self, set: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.Address: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    @overload
    def getAddressRanges(self) -> ghidra.program.model.address.AddressRangeIterator: ...

    @overload
    def getAddressRanges(self, forward: bool) -> ghidra.program.model.address.AddressRangeIterator: ...

    @overload
    def getAddressRanges(self, start: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.address.AddressRangeIterator: ...

    def getAddressSourceInfo(self, address: ghidra.program.model.address.Address) -> ghidra.program.database.mem.AddressSourceInfo: ...

    @overload
    def getAddresses(self, forward: bool) -> ghidra.program.model.address.AddressIterator: ...

    @overload
    def getAddresses(self, start: ghidra.program.model.address.Address, forward: bool) -> ghidra.program.model.address.AddressIterator: ...

    def getAllFileBytes(self) -> List[ghidra.program.database.mem.FileBytes]: ...

    def getAllInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView: ...

    @overload
    def getBlock(self, blockName: unicode) -> ghidra.program.model.mem.MemoryBlock: ...

    @overload
    def getBlock(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.mem.MemoryBlock: ...

    def getBlocks(self) -> List[ghidra.program.model.mem.MemoryBlock]: ...

    def getByte(self, addr: ghidra.program.model.address.Address) -> int: ...

    @overload
    def getBytes(self, addr: ghidra.program.model.address.Address, dest: List[int]) -> int: ...

    @overload
    def getBytes(self, addr: ghidra.program.model.address.Address, dest: List[int], dIndex: int, size: int) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getExecuteSet(self) -> ghidra.program.model.address.AddressSetView: ...

    def getFirstRange(self) -> ghidra.program.model.address.AddressRange: ...

    def getInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView: ...

    @overload
    def getInt(self, addr: ghidra.program.model.address.Address) -> int: ...

    @overload
    def getInt(self, addr: ghidra.program.model.address.Address, bigEndian: bool) -> int: ...

    @overload
    def getInts(self, addr: ghidra.program.model.address.Address, dest: List[int]) -> int: ...

    @overload
    def getInts(self, addr: ghidra.program.model.address.Address, dest: List[int], dIndex: int, nElem: int) -> int: ...

    @overload
    def getInts(self, addr: ghidra.program.model.address.Address, dest: List[int], dIndex: int, nElem: int, isBigEndian: bool) -> int: ...

    def getLastRange(self) -> ghidra.program.model.address.AddressRange: ...

    def getLiveMemoryHandler(self) -> ghidra.program.model.mem.LiveMemoryHandler: ...

    def getLoadedAndInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView: ...

    @overload
    def getLong(self, addr: ghidra.program.model.address.Address) -> long: ...

    @overload
    def getLong(self, addr: ghidra.program.model.address.Address, bigEndian: bool) -> long: ...

    @overload
    def getLongs(self, addr: ghidra.program.model.address.Address, dest: List[long]) -> int: ...

    @overload
    def getLongs(self, addr: ghidra.program.model.address.Address, dest: List[long], dIndex: int, nElem: int) -> int: ...

    @overload
    def getLongs(self, addr: ghidra.program.model.address.Address, dest: List[long], dIndex: int, nElem: int, isBigEndian: bool) -> int: ...

    def getMaxAddress(self) -> ghidra.program.model.address.Address: ...

    def getMinAddress(self) -> ghidra.program.model.address.Address: ...

    def getNumAddressRanges(self) -> int: ...

    def getNumAddresses(self) -> long: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getRangeContaining(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange: ...

    @overload
    def getShort(self, addr: ghidra.program.model.address.Address) -> int: ...

    @overload
    def getShort(self, addr: ghidra.program.model.address.Address, bigEndian: bool) -> int: ...

    @overload
    def getShorts(self, addr: ghidra.program.model.address.Address, dest: List[int]) -> int: ...

    @overload
    def getShorts(self, addr: ghidra.program.model.address.Address, dest: List[int], dIndex: int, nElem: int) -> int: ...

    @overload
    def getShorts(self, addr: ghidra.program.model.address.Address, dest: List[int], dIndex: int, nElem: int, isBigEndian: bool) -> int: ...

    def getSize(self) -> long: ...

    def hasSameAddresses(self, addrSet: ghidra.program.model.address.AddressSetView) -> bool: ...

    def hashCode(self) -> int: ...

    def intersect(self, addrSet: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSet: ...

    def intersectRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressSet: ...

    @overload
    def intersects(self, addrSet: ghidra.program.model.address.AddressSetView) -> bool: ...

    @overload
    def intersects(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> bool: ...

    def isBigEndian(self) -> bool: ...

    def isEmpty(self) -> bool: ...

    def isExternalBlockAddress(self, __a0: ghidra.program.model.address.Address) -> bool: ...

    @staticmethod
    def isValidMemoryBlockName(__a0: unicode) -> bool: ...

    @overload
    def iterator(self) -> Iterator[ghidra.program.model.address.AddressRange]: ...

    @overload
    def iterator(self, forward: bool) -> Iterator[ghidra.program.model.address.AddressRange]: ...

    @overload
    def iterator(self, start: ghidra.program.model.address.Address, forward: bool) -> Iterator[ghidra.program.model.address.AddressRange]: ...

    def join(self, blockOne: ghidra.program.model.mem.MemoryBlock, blockTwo: ghidra.program.model.mem.MemoryBlock) -> ghidra.program.model.mem.MemoryBlock: ...

    def locateAddressesForFileBytesOffset(self, __a0: ghidra.program.database.mem.FileBytes, __a1: long) -> List[object]: ...

    def locateAddressesForFileOffset(self, __a0: long) -> List[object]: ...

    def moveBlock(self, block: ghidra.program.model.mem.MemoryBlock, newStartAddr: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def printRanges(self) -> unicode:
        """
        Returns a string displaying the ranges in this set.
        @return a string displaying the ranges in this set.
        """
        ...

    def removeBlock(self, block: ghidra.program.model.mem.MemoryBlock, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def setByte(self, addr: ghidra.program.model.address.Address, value: int) -> None: ...

    @overload
    def setBytes(self, addr: ghidra.program.model.address.Address, source: List[int]) -> None: ...

    @overload
    def setBytes(self, addr: ghidra.program.model.address.Address, source: List[int], sIndex: int, size: int) -> None: ...

    @overload
    def setInt(self, addr: ghidra.program.model.address.Address, value: int) -> None: ...

    @overload
    def setInt(self, addr: ghidra.program.model.address.Address, value: int, bigEndian: bool) -> None: ...

    def setLiveMemoryHandler(self, handler: ghidra.program.model.mem.LiveMemoryHandler) -> None: ...

    @overload
    def setLong(self, addr: ghidra.program.model.address.Address, value: long) -> None: ...

    @overload
    def setLong(self, addr: ghidra.program.model.address.Address, value: long, bigEndian: bool) -> None: ...

    @overload
    def setShort(self, addr: ghidra.program.model.address.Address, value: int) -> None: ...

    @overload
    def setShort(self, addr: ghidra.program.model.address.Address, value: int, bigEndian: bool) -> None: ...

    def split(self, block: ghidra.program.model.mem.MemoryBlock, addr: ghidra.program.model.address.Address) -> None: ...

    def spliterator(self) -> java.util.Spliterator: ...

    def subtract(self, addrSet: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSet: ...

    def toList(self) -> List[ghidra.program.model.address.AddressRange]:
        """
        Returns a list of the AddressRanges in this set.
        @return a list of the AddressRanges in this set.
        """
        ...

    def toString(self) -> unicode: ...

    @staticmethod
    def trimEnd(__a0: ghidra.program.model.address.AddressSetView, __a1: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressSetView: ...

    @staticmethod
    def trimStart(__a0: ghidra.program.model.address.AddressSetView, __a1: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressSetView: ...

    def union(self, addrSet: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSet: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def xor(self, addrSet: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSet: ...

    @property
    def addressRanges(self) -> ghidra.program.model.address.AddressRangeIterator: ...

    @property
    def allFileBytes(self) -> List[object]: ...

    @property
    def allInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView: ...

    @property
    def bigEndian(self) -> bool: ...

    @property
    def blocks(self) -> List[ghidra.program.model.mem.MemoryBlock]: ...

    @property
    def empty(self) -> bool: ...

    @property
    def executeSet(self) -> ghidra.program.model.address.AddressSetView: ...

    @property
    def firstRange(self) -> ghidra.program.model.address.AddressRange: ...

    @property
    def initializedAddressSet(self) -> ghidra.program.model.address.AddressSetView: ...

    @property
    def lastRange(self) -> ghidra.program.model.address.AddressRange: ...

    @property
    def liveMemoryHandler(self) -> ghidra.program.model.mem.LiveMemoryHandler: ...

    @liveMemoryHandler.setter
    def liveMemoryHandler(self, value: ghidra.program.model.mem.LiveMemoryHandler) -> None: ...

    @property
    def loadedAndInitializedAddressSet(self) -> ghidra.program.model.address.AddressSetView: ...

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def numAddressRanges(self) -> int: ...

    @property
    def numAddresses(self) -> long: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...

    @property
    def size(self) -> long: ...