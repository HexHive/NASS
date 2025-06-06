import ghidra.app.plugin.core.debug.service.modules
import ghidra.app.services
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.modules
import java.lang
import java.util


class DefaultSectionMapProposal(ghidra.app.plugin.core.debug.service.modules.AbstractMapProposal, ghidra.app.services.SectionMapProposal):





    class DefaultSectionMapEntry(ghidra.app.plugin.core.debug.service.modules.AbstractMapEntry, ghidra.app.services.SectionMapProposal.SectionMapEntry):








        def equals(self, __a0: object) -> bool: ...

        def getBlock(self) -> ghidra.program.model.mem.MemoryBlock: ...

        def getClass(self) -> java.lang.Class: ...

        def getFromLifespan(self) -> ghidra.trace.model.Lifespan: ...

        def getFromObject(self) -> object: ...

        def getFromRange(self) -> ghidra.program.model.address.AddressRange: ...

        def getFromTrace(self) -> ghidra.trace.model.Trace: ...

        def getFromTraceLocation(self) -> ghidra.trace.model.TraceLocation: ...

        def getMappingLength(self) -> long: ...

        def getModule(self) -> ghidra.trace.model.modules.TraceModule: ...

        def getSection(self) -> ghidra.trace.model.modules.TraceSection: ...

        def getToObject(self) -> object: ...

        def getToProgram(self) -> ghidra.program.model.listing.Program: ...

        def getToProgramLocation(self) -> ghidra.program.util.ProgramLocation: ...

        def getToRange(self) -> ghidra.program.model.address.AddressRange: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def setBlock(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.program.model.mem.MemoryBlock) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def block(self) -> ghidra.program.model.mem.MemoryBlock: ...

        @property
        def fromLifespan(self) -> ghidra.trace.model.Lifespan: ...

        @property
        def fromRange(self) -> ghidra.program.model.address.AddressRange: ...

        @property
        def module(self) -> ghidra.trace.model.modules.TraceModule: ...

        @property
        def section(self) -> ghidra.trace.model.modules.TraceSection: ...

        @property
        def toRange(self) -> ghidra.program.model.address.AddressRange: ...





    def computeMap(self) -> java.util.Map: ...

    def computeScore(self) -> float: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def flatten(__a0: java.util.Collection) -> java.util.Collection: ...

    def getClass(self) -> java.lang.Class: ...

    def getModule(self) -> ghidra.trace.model.modules.TraceModule: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    @overload
    def getToObject(self, __a0: ghidra.trace.model.modules.TraceSection) -> ghidra.program.model.mem.MemoryBlock: ...

    @overload
    def getToObject(self, __a0: object) -> object: ...

    def getTrace(self) -> ghidra.trace.model.Trace: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def removeOverlapping(__a0: java.util.Collection) -> java.util.Set: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def module(self) -> ghidra.trace.model.modules.TraceModule: ...