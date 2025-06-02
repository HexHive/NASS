from typing import List
import ghidra.app.plugin.core.debug.service.emulation
import ghidra.dbg.util
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.trace.model
import ghidra.trace.model.thread
import ghidra.trace.model.time
import java.lang
import java.util


class ProgramEmulationUtils(java.lang.Enum):
    BLOCK_NAME_STACK: unicode = u'STACK'
    EMULATION_STARTED_AT: unicode = u'Emulation started at '







    @staticmethod
    def allocateStack(__a0: ghidra.trace.model.Trace, __a1: long, __a2: ghidra.trace.model.thread.TraceThread, __a3: ghidra.program.model.listing.Program, __a4: long) -> ghidra.program.model.address.AddressRange: ...

    @staticmethod
    def allocateStackCustom(__a0: ghidra.trace.model.Trace, __a1: long, __a2: ghidra.trace.model.thread.TraceThread, __a3: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressRange: ...

    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    @staticmethod
    def computePattern(__a0: ghidra.trace.model.Trace, __a1: java.lang.Class) -> ghidra.dbg.util.PathPattern: ...

    @staticmethod
    def computePatternRegion(__a0: ghidra.trace.model.Trace) -> ghidra.dbg.util.PathPattern: ...

    @staticmethod
    def computePatternThread(__a0: ghidra.trace.model.Trace) -> ghidra.dbg.util.PathPattern: ...

    def describeConstable(self) -> java.util.Optional: ...

    @staticmethod
    def doLaunchEmulationThread(__a0: ghidra.trace.model.Trace, __a1: long, __a2: ghidra.program.model.listing.Program, __a3: ghidra.program.model.address.Address, __a4: ghidra.program.model.address.Address) -> ghidra.trace.model.thread.TraceThread: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    @staticmethod
    def getModuleName(__a0: ghidra.program.model.listing.Program) -> unicode: ...

    @staticmethod
    def getRegionFlags(__a0: ghidra.program.model.mem.MemoryBlock) -> java.util.Set: ...

    @staticmethod
    def getTraceName(__a0: ghidra.program.model.listing.Program) -> unicode: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def initializeRegisters(__a0: ghidra.trace.model.Trace, __a1: long, __a2: ghidra.trace.model.thread.TraceThread, __a3: ghidra.program.model.listing.Program, __a4: ghidra.program.model.address.Address, __a5: ghidra.program.model.address.Address, __a6: ghidra.program.model.address.AddressRange) -> None: ...

    @staticmethod
    def isEmulatedProgram(__a0: ghidra.trace.model.Trace) -> bool: ...

    @staticmethod
    def launchEmulationThread(__a0: ghidra.trace.model.Trace, __a1: long, __a2: ghidra.program.model.listing.Program, __a3: ghidra.program.model.address.Address, __a4: ghidra.program.model.address.Address) -> ghidra.trace.model.thread.TraceThread: ...

    @staticmethod
    def launchEmulationTrace(__a0: ghidra.program.model.listing.Program, __a1: ghidra.program.model.address.Address, __a2: object) -> ghidra.trace.model.Trace: ...

    @staticmethod
    def loadExecutable(__a0: ghidra.trace.model.time.TraceSnapshot, __a1: ghidra.program.model.listing.Program) -> None: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def spawnThread(__a0: ghidra.trace.model.Trace, __a1: long) -> ghidra.trace.model.thread.TraceThread: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

