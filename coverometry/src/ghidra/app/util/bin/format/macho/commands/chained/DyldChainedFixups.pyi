from typing import List
import ghidra.app.util.bin.format.macho.commands.chained
import ghidra.app.util.bin.format.macho.dyld
import ghidra.program.model.address
import java.lang


class DyldChainedFixups(object):




    def __init__(self, program: ghidra.program.model.listing.Program, header: ghidra.app.util.bin.format.macho.MachHeader, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new {@link DyldChainedFixups}
        @param program The {@link Program}
        @param header The Mach-O header
        @param log The log
        @param monitor A cancelable task monitor.
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def processChainedFixups(self) -> List[ghidra.program.model.address.Address]:
        """
        Fixes up any chained fixups.  Relies on the __thread_starts section being present.
        @return A list of addresses where chained fixups were performed.
        @throws Exception if there was a problem reading/writing memory.
        """
        ...

    def processPointerChain(self, __a0: ghidra.app.util.bin.format.macho.commands.chained.DyldChainedImports, __a1: List[object], __a2: ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr.DyldChainType, __a3: long, __a4: long, __a5: long) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

