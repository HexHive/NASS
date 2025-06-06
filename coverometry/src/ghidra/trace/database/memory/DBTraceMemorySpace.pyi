from typing import List
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.mem
import ghidra.trace.database.listing
import ghidra.trace.database.memory
import ghidra.trace.database.space
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.memory
import ghidra.trace.model.thread
import ghidra.util.task
import java.lang
import java.nio
import java.util
import java.util.concurrent.locks
import java.util.function


class DBTraceMemorySpace(object, ghidra.trace.model.memory.TraceMemorySpace, ghidra.trace.database.memory.InternalTraceMemoryOperations, ghidra.trace.database.space.DBTraceSpaceBased):
    BLOCKS_PER_BUFFER: int = 256
    BLOCK_MASK: int = -4096
    BLOCK_SHIFT: int = 12
    BLOCK_SIZE: int = 4096
    DEPENDENT_COMPRESSED_SIZE_TOLERANCE: int = 1024



    def __init__(self, __a0: ghidra.trace.database.memory.DBTraceMemoryManager, __a1: db.DBHandle, __a2: ghidra.program.model.address.AddressSpace, __a3: ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry, __a4: ghidra.trace.model.thread.TraceThread): ...



    @overload
    def addRegion(self, __a0: unicode, __a1: ghidra.trace.model.Lifespan, __a2: ghidra.program.model.address.AddressRange, __a3: List[ghidra.trace.model.memory.TraceMemoryFlag]) -> ghidra.trace.model.memory.TraceMemoryRegion: ...

    @overload
    def addRegion(self, __a0: unicode, __a1: ghidra.trace.model.Lifespan, __a2: ghidra.program.model.address.AddressRange, __a3: java.util.Collection) -> ghidra.trace.model.memory.TraceMemoryRegion: ...

    @overload
    def assertInSpace(self, __a0: ghidra.program.model.address.Address) -> long: ...

    @overload
    def assertInSpace(self, __a0: ghidra.program.model.address.AddressRange) -> None: ...

    @staticmethod
    def create(__a0: ghidra.program.model.address.AddressSpace, __a1: ghidra.trace.model.thread.TraceThread, __a2: int) -> ghidra.trace.database.space.DBTraceSpaceKey: ...

    @overload
    def createRegion(self, __a0: unicode, __a1: long, __a2: ghidra.program.model.address.AddressRange, __a3: List[ghidra.trace.model.memory.TraceMemoryFlag]) -> ghidra.trace.model.memory.TraceMemoryRegion: ...

    @overload
    def createRegion(self, __a0: unicode, __a1: long, __a2: ghidra.program.model.address.AddressRange, __a3: java.util.Collection) -> ghidra.trace.model.memory.TraceMemoryRegion: ...

    def equals(self, __a0: object) -> bool: ...

    def explainLanguages(self, __a0: ghidra.program.model.address.AddressSpace) -> unicode: ...

    def findBytes(self, __a0: long, __a1: ghidra.program.model.address.AddressRange, __a2: java.nio.ByteBuffer, __a3: java.nio.ByteBuffer, __a4: bool, __a5: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address: ...

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @overload
    def getAddressesWithState(self, __a0: long, __a1: java.util.function.Predicate) -> ghidra.program.model.address.AddressSetView: ...

    @overload
    def getAddressesWithState(self, __a0: ghidra.trace.model.Lifespan, __a1: java.util.function.Predicate) -> ghidra.program.model.address.AddressSetView: ...

    @overload
    def getAddressesWithState(self, __a0: long, __a1: ghidra.program.model.address.AddressSetView, __a2: java.util.function.Predicate) -> ghidra.program.model.address.AddressSetView: ...

    @overload
    def getAddressesWithState(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.AddressSetView, __a2: java.util.function.Predicate) -> ghidra.program.model.address.AddressSetView: ...

    def getAllRegions(self) -> java.util.Collection: ...

    def getBlockSize(self) -> int: ...

    @overload
    def getBufferAt(self, __a0: long, __a1: ghidra.program.model.address.Address) -> ghidra.program.model.mem.MemBuffer: ...

    @overload
    def getBufferAt(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: java.nio.ByteOrder) -> ghidra.program.model.mem.MemBuffer: ...

    @overload
    def getBytes(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: java.nio.ByteBuffer) -> int: ...

    @overload
    def getBytes(self, __a0: long, __a1: ghidra.program.model.lang.Register, __a2: java.nio.ByteBuffer) -> int: ...

    @overload
    def getBytes(self, __a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.program.model.lang.Register, __a3: java.nio.ByteBuffer) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeSpace(self, __a0: bool) -> ghidra.trace.database.listing.DBTraceCodeSpace: ...

    def getFirstChange(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.AddressRange) -> long: ...

    def getFrameLevel(self) -> int: ...

    def getLiveRegionByPath(self, __a0: long, __a1: unicode) -> ghidra.trace.database.memory.DBTraceMemoryRegion: ...

    def getLock(self) -> java.util.concurrent.locks.ReadWriteLock: ...

    def getMostRecentStateEntry(self, __a0: long, __a1: ghidra.program.model.address.Address) -> java.util.Map.Entry: ...

    @overload
    def getMostRecentStates(self, __a0: ghidra.trace.model.TraceAddressSnapRange) -> java.lang.Iterable: ...

    @overload
    def getMostRecentStates(self, __a0: long, __a1: ghidra.program.model.address.AddressRange) -> java.lang.Iterable: ...

    def getRegionContaining(self, __a0: long, __a1: ghidra.program.model.address.Address) -> ghidra.trace.model.memory.TraceMemoryRegion: ...

    def getRegionsAddressSet(self, __a0: long) -> ghidra.program.model.address.AddressSetView: ...

    def getRegionsAddressSetWith(self, __a0: long, __a1: java.util.function.Predicate) -> ghidra.program.model.address.AddressSetView: ...

    def getRegionsAtSnap(self, __a0: long) -> java.util.Collection: ...

    def getRegionsIntersecting(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.AddressRange) -> java.util.Collection: ...

    def getSnapOfMostRecentChangeToBlock(self, __a0: long, __a1: ghidra.program.model.address.Address) -> long: ...

    def getSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @overload
    def getState(self, __a0: long, __a1: ghidra.program.model.address.Address) -> ghidra.trace.model.memory.TraceMemoryState: ...

    @overload
    def getState(self, __a0: long, __a1: ghidra.program.model.lang.Register) -> ghidra.trace.model.memory.TraceMemoryState: ...

    @overload
    def getState(self, __a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.program.model.lang.Register) -> ghidra.trace.model.memory.TraceMemoryState: ...

    @overload
    def getStates(self, __a0: long, __a1: ghidra.program.model.address.AddressRange) -> java.util.Collection: ...

    @overload
    def getStates(self, __a0: long, __a1: ghidra.program.model.lang.Register) -> java.util.Collection: ...

    @overload
    def getStates(self, __a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.program.model.lang.Register) -> java.util.Collection: ...

    def getThread(self) -> ghidra.trace.model.thread.TraceThread: ...

    def getTrace(self) -> ghidra.trace.model.Trace: ...

    @overload
    def getValue(self, __a0: long, __a1: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue: ...

    @overload
    def getValue(self, __a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue: ...

    def getViewBytes(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: java.nio.ByteBuffer) -> int: ...

    def getViewMostRecentStateEntry(self, __a0: long, __a1: ghidra.program.model.address.Address) -> java.util.Map.Entry: ...

    def getViewState(self, __a0: long, __a1: ghidra.program.model.address.Address) -> java.util.Map.Entry: ...

    @overload
    def getViewValue(self, __a0: long, __a1: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue: ...

    @overload
    def getViewValue(self, __a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.RegisterValue: ...

    def hashCode(self) -> int: ...

    def invalidateCache(self) -> None: ...

    def isKnown(self, __a0: long, __a1: ghidra.program.model.address.AddressRange) -> bool: ...

    def isMySpace(self, __a0: ghidra.program.model.address.AddressSpace) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def pack(self) -> None: ...

    @overload
    def putBytes(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: java.nio.ByteBuffer) -> int: ...

    @overload
    def putBytes(self, __a0: long, __a1: ghidra.program.model.lang.Register, __a2: java.nio.ByteBuffer) -> int: ...

    @overload
    def putBytes(self, __a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.program.model.lang.Register, __a3: java.nio.ByteBuffer) -> int: ...

    def removeBytes(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: int) -> None: ...

    @overload
    def removeValue(self, __a0: long, __a1: ghidra.program.model.lang.Register) -> None: ...

    @overload
    def removeValue(self, __a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.program.model.lang.Register) -> None: ...

    @staticmethod
    def requireOne(__a0: java.util.Collection, __a1: ghidra.program.model.lang.Register) -> ghidra.trace.model.memory.TraceMemoryState: ...

    @overload
    def setState(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: ghidra.trace.model.memory.TraceMemoryState) -> None: ...

    @overload
    def setState(self, __a0: long, __a1: ghidra.program.model.address.AddressRange, __a2: ghidra.trace.model.memory.TraceMemoryState) -> None: ...

    @overload
    def setState(self, __a0: long, __a1: ghidra.program.model.address.AddressSetView, __a2: ghidra.trace.model.memory.TraceMemoryState) -> None: ...

    @overload
    def setState(self, __a0: long, __a1: ghidra.program.model.lang.Register, __a2: ghidra.trace.model.memory.TraceMemoryState) -> None: ...

    @overload
    def setState(self, __a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.program.model.lang.Register, __a3: ghidra.trace.model.memory.TraceMemoryState) -> None: ...

    @overload
    def setState(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.address.Address, __a3: ghidra.trace.model.memory.TraceMemoryState) -> None: ...

    @overload
    def setValue(self, __a0: long, __a1: ghidra.program.model.lang.RegisterValue) -> int: ...

    @overload
    def setValue(self, __a0: ghidra.trace.model.guest.TracePlatform, __a1: long, __a2: ghidra.program.model.lang.RegisterValue) -> int: ...

    def toAddress(self, __a0: long) -> ghidra.program.model.address.Address: ...

    def toOverlay(self, __a0: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def allRegions(self) -> java.util.Collection: ...

    @property
    def blockSize(self) -> int: ...

    @property
    def frameLevel(self) -> int: ...

    @property
    def lock(self) -> java.util.concurrent.locks.ReadWriteLock: ...

    @property
    def space(self) -> ghidra.program.model.address.AddressSpace: ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread: ...

    @property
    def trace(self) -> ghidra.trace.model.Trace: ...