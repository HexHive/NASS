import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.commands
import ghidra.app.util.importer
import ghidra.program.flatapi
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class CodeSignatureCommand(ghidra.app.util.bin.format.macho.commands.LinkEditDataCommand):
    """
    Represents a LC_CODE_SIGNATURE command.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCommandName(self) -> unicode: ...

    def getCommandSize(self) -> int:
        """
        Gets the size of this load command in bytes
        @return The size of this load command in bytes
        """
        ...

    def getCommandType(self) -> int:
        """
        Gets the type of this load command
        @return The type of this load command
        """
        ...

    def getLinkerDataOffset(self) -> int: ...

    def getLinkerDataSize(self) -> int: ...

    def getStartIndex(self) -> long:
        """
        Returns the binary start index of this load command
        @return the binary start index of this load command
        """
        ...

    def hashCode(self) -> int: ...

    def markup(self, program: ghidra.program.model.listing.Program, header: ghidra.app.util.bin.format.macho.MachHeader, source: unicode, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None: ...

    def markupRawBinary(self, header: ghidra.app.util.bin.format.macho.MachHeader, api: ghidra.program.flatapi.FlatProgramAPI, baseAddress: ghidra.program.model.address.Address, parentModule: ghidra.program.model.listing.ProgramModule, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def setEndian(data: ghidra.program.model.listing.Data, bigEndian: bool) -> None:
        """
        Recursively sets the given {@link Data} and its components to big/little endian
        @param data The {@link Data}
        @param bigEndian True to set to big endian; false to set to little endian
        @throws Exception if there was a problem setting the endianness
        """
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

