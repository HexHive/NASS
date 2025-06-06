import ghidra.app.services
import ghidra.framework.model
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.util
import ghidra.trace.model
import ghidra.trace.model.memory
import ghidra.trace.model.modules
import ghidra.trace.model.program
import ghidra.util.task
import java.lang
import java.util
import java.util.concurrent


class DebuggerStaticMappingService(object):





    class MappedAddressRange(object, java.lang.Comparable):




        def __init__(self, __a0: ghidra.program.model.address.AddressRange, __a1: ghidra.program.model.address.AddressRange): ...



        @overload
        def compareTo(self, __a0: ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDestinationAddressRange(self) -> ghidra.program.model.address.AddressRange: ...

        def getShift(self) -> long: ...

        def getSourceAddressRange(self) -> ghidra.program.model.address.AddressRange: ...

        def hashCode(self) -> int: ...

        @overload
        def mapDestinationToSource(self, __a0: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

        @overload
        def mapDestinationToSource(self, __a0: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange: ...

        @overload
        def mapSourceToDestination(self, __a0: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

        @overload
        def mapSourceToDestination(self, __a0: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange: ...

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
        def destinationAddressRange(self) -> ghidra.program.model.address.AddressRange: ...

        @property
        def shift(self) -> long: ...

        @property
        def sourceAddressRange(self) -> ghidra.program.model.address.AddressRange: ...





    def addChangeListener(self, __a0: ghidra.app.services.DebuggerStaticMappingChangeListener) -> None: ...

    def addIdentityMapping(self, __a0: ghidra.trace.model.Trace, __a1: ghidra.program.model.listing.Program, __a2: ghidra.trace.model.Lifespan, __a3: bool) -> None: ...

    @overload
    def addMapping(self, __a0: ghidra.app.services.MapEntry, __a1: bool) -> None: ...

    @overload
    def addMapping(self, __a0: ghidra.trace.model.TraceLocation, __a1: ghidra.program.util.ProgramLocation, __a2: long, __a3: bool) -> None: ...

    def addMappings(self, __a0: java.util.Collection, __a1: ghidra.util.task.TaskMonitor, __a2: bool, __a3: unicode) -> None: ...

    def addModuleMappings(self, __a0: java.util.Collection, __a1: ghidra.util.task.TaskMonitor, __a2: bool) -> None: ...

    def addRegionMappings(self, __a0: java.util.Collection, __a1: ghidra.util.task.TaskMonitor, __a2: bool) -> None: ...

    def addSectionMappings(self, __a0: java.util.Collection, __a1: ghidra.util.task.TaskMonitor, __a2: bool) -> None: ...

    def changesSettled(self) -> java.util.concurrent.CompletableFuture: ...

    def equals(self, __a0: object) -> bool: ...

    def findBestModuleProgram(self, __a0: ghidra.program.model.address.AddressSpace, __a1: ghidra.trace.model.modules.TraceModule) -> ghidra.framework.model.DomainFile: ...

    def getClass(self) -> java.lang.Class: ...

    def getDynamicLocationFromStatic(self, __a0: ghidra.trace.model.program.TraceProgramView, __a1: ghidra.program.util.ProgramLocation) -> ghidra.program.util.ProgramLocation: ...

    @overload
    def getOpenMappedLocation(self, __a0: ghidra.trace.model.TraceLocation) -> ghidra.program.util.ProgramLocation: ...

    @overload
    def getOpenMappedLocation(self, __a0: ghidra.trace.model.Trace, __a1: ghidra.program.util.ProgramLocation, __a2: long) -> ghidra.trace.model.TraceLocation: ...

    def getOpenMappedLocations(self, __a0: ghidra.program.util.ProgramLocation) -> java.util.Set: ...

    def getOpenMappedProgramsAtSnap(self, __a0: ghidra.trace.model.Trace, __a1: long) -> java.util.Set: ...

    @overload
    def getOpenMappedViews(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.program.model.address.AddressSetView) -> java.util.Map: ...

    @overload
    def getOpenMappedViews(self, __a0: ghidra.trace.model.Trace, __a1: ghidra.program.model.address.AddressSetView, __a2: long) -> java.util.Map: ...

    def getStaticLocationFromDynamic(self, __a0: ghidra.program.util.ProgramLocation) -> ghidra.program.util.ProgramLocation: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openMappedProgramsInView(self, __a0: ghidra.trace.model.Trace, __a1: ghidra.program.model.address.AddressSetView, __a2: long, __a3: java.util.Set) -> java.util.Set: ...

    @overload
    def proposeModuleMap(self, __a0: ghidra.trace.model.modules.TraceModule, __a1: ghidra.program.model.listing.Program) -> ghidra.app.services.ModuleMapProposal: ...

    @overload
    def proposeModuleMap(self, __a0: ghidra.trace.model.modules.TraceModule, __a1: java.util.Collection) -> ghidra.app.services.ModuleMapProposal: ...

    def proposeModuleMaps(self, __a0: java.util.Collection, __a1: java.util.Collection) -> java.util.Map: ...

    @overload
    def proposeRegionMap(self, __a0: java.util.Collection, __a1: ghidra.program.model.listing.Program) -> ghidra.app.services.RegionMapProposal: ...

    @overload
    def proposeRegionMap(self, __a0: ghidra.trace.model.memory.TraceMemoryRegion, __a1: ghidra.program.model.listing.Program, __a2: ghidra.program.model.mem.MemoryBlock) -> ghidra.app.services.RegionMapProposal: ...

    def proposeRegionMaps(self, __a0: java.util.Collection, __a1: java.util.Collection) -> java.util.Map: ...

    @overload
    def proposeSectionMap(self, __a0: ghidra.trace.model.modules.TraceModule, __a1: ghidra.program.model.listing.Program) -> ghidra.app.services.SectionMapProposal: ...

    @overload
    def proposeSectionMap(self, __a0: ghidra.trace.model.modules.TraceModule, __a1: java.util.Collection) -> ghidra.app.services.SectionMapProposal: ...

    @overload
    def proposeSectionMap(self, __a0: ghidra.trace.model.modules.TraceSection, __a1: ghidra.program.model.listing.Program, __a2: ghidra.program.model.mem.MemoryBlock) -> ghidra.app.services.SectionMapProposal: ...

    def proposeSectionMaps(self, __a0: java.util.Collection, __a1: java.util.Collection) -> java.util.Map: ...

    def removeChangeListener(self, __a0: ghidra.app.services.DebuggerStaticMappingChangeListener) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

