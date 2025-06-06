import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.memory
import java.lang


class RegionRow(object):




    def __init__(self, __a0: ghidra.trace.model.memory.TraceMemoryRegion): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCreatedSnap(self) -> long: ...

    def getDestroyedSnap(self) -> unicode: ...

    def getLength(self) -> long: ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan: ...

    def getMaxAddress(self) -> ghidra.program.model.address.Address: ...

    def getMinAddress(self) -> ghidra.program.model.address.Address: ...

    def getName(self) -> unicode: ...

    def getRange(self) -> ghidra.program.model.address.AddressRange: ...

    def getRegion(self) -> ghidra.trace.model.memory.TraceMemoryRegion: ...

    def hashCode(self) -> int: ...

    def isExecute(self) -> bool: ...

    def isRead(self) -> bool: ...

    def isVolatile(self) -> bool: ...

    def isWrite(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setExecute(self, __a0: bool) -> None: ...

    def setName(self, __a0: unicode) -> None: ...

    def setRead(self, __a0: bool) -> None: ...

    def setVolatile(self, __a0: bool) -> None: ...

    def setWrite(self, __a0: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def createdSnap(self) -> long: ...

    @property
    def destroyedSnap(self) -> unicode: ...

    @property
    def execute(self) -> bool: ...

    @execute.setter
    def execute(self, value: bool) -> None: ...

    @property
    def length(self) -> long: ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan: ...

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange: ...

    @property
    def read(self) -> bool: ...

    @read.setter
    def read(self, value: bool) -> None: ...

    @property
    def region(self) -> ghidra.trace.model.memory.TraceMemoryRegion: ...

    @property
    def volatile(self) -> bool: ...

    @volatile.setter
    def volatile(self, value: bool) -> None: ...

    @property
    def write(self) -> bool: ...

    @write.setter
    def write(self, value: bool) -> None: ...