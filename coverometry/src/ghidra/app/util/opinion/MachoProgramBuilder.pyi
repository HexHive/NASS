from typing import List
import ghidra.app.util.bin
import ghidra.app.util.bin.format.macho
import ghidra.app.util.importer
import ghidra.program.database.mem
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class MachoProgramBuilder(object):
    """
    Builds up a Mach-O Program by parsing the Mach-O headers.
    """

    BLOCK_SOURCE_NAME: unicode = u'Mach-O Loader'







    @staticmethod
    def buildProgram(program: ghidra.program.model.listing.Program, provider: ghidra.app.util.bin.ByteProvider, fileBytes: ghidra.program.database.mem.FileBytes, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Builds up a Mach-O {@link Program}.
        @param program The {@link Program} to build up.
        @param provider The {@link ByteProvider} that contains the Mach-O's bytes.
        @param fileBytes Where the Mach-O's bytes came from.
        @param log The log.
        @param monitor A cancelable task monitor.
        @throws Exception if a problem occurs.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def processChainedFixups(self, header: ghidra.app.util.bin.format.macho.MachHeader) -> List[ghidra.program.model.address.Address]: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

