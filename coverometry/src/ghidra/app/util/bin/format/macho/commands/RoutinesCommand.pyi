import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.commands
import ghidra.app.util.importer
import ghidra.program.flatapi
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class RoutinesCommand(ghidra.app.util.bin.format.macho.commands.LoadCommand):
    """
    Represents a routines_command and routines_command_64 structure
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

    def getInitializationRoutineAddress(self) -> long:
        """
        Address of initialization routine.
        @return address of initialization routine
        """
        ...

    def getInitializationRoutineModuleIndex(self) -> long:
        """
        Index into the module table that the init routine is defined in.
        @return index into the module table that the init routine is defined in
        """
        ...

    def getLinkerDataOffset(self) -> int:
        """
        Gets the file offset of this load command's "linker data".  Not all load commands with data
         will have linker data.  Linker data typically resides in the __LINKEDIT segment.
        @return The file offset of this load command's "linker data", or 0 if it has no linker data
        """
        ...

    def getLinkerDataSize(self) -> int:
        """
        Gets the file size of this load command's "linker data". Not all load commands with data
         will have linker data.  Linker data typically resides in the __LINKEDIT segment.
        @return The file size of this load command's "linker data", or 0 if it has no linker data
        """
        ...

    def getReserved1(self) -> long: ...

    def getReserved2(self) -> long: ...

    def getReserved3(self) -> long: ...

    def getReserved4(self) -> long: ...

    def getReserved5(self) -> long: ...

    def getReserved6(self) -> long: ...

    def getStartIndex(self) -> long:
        """
        Returns the binary start index of this load command
        @return the binary start index of this load command
        """
        ...

    def hashCode(self) -> int: ...

    def markup(self, program: ghidra.program.model.listing.Program, header: ghidra.app.util.bin.format.macho.MachHeader, source: unicode, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Marks up this {@link LoadCommand} data with data structures and comments.  Assumes the
         program was imported as a Mach-O.
        @param program The {@link Program} to mark up
        @param header The Mach-O header
        @param source A name that represents where the header came from (could be null)
        @param monitor A cancellable task monitor
        @param log The log
        @throws CancelledException if the user cancelled the operation
        """
        ...

    def markupRawBinary(self, header: ghidra.app.util.bin.format.macho.MachHeader, api: ghidra.program.flatapi.FlatProgramAPI, baseAddress: ghidra.program.model.address.Address, parentModule: ghidra.program.model.listing.ProgramModule, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog) -> None:
        """
        Marks-up this {@link LoadCommand} with data structures and comments.  Assumes the program
         was imported as a Raw Binary.
        @param header The Mach-O header
        @param api A {@link FlatProgramAPI}
        @param baseAddress The base address of the program
        @param parentModule The parent {@link ProgramModule module} to create fragments
        @param monitor A cancellable task monitor
        @param log The log
        @see MachoBinaryAnalysisCommand
        """
        ...

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

    @property
    def commandName(self) -> unicode: ...

    @property
    def initializationRoutineAddress(self) -> long: ...

    @property
    def initializationRoutineModuleIndex(self) -> long: ...

    @property
    def reserved1(self) -> long: ...

    @property
    def reserved2(self) -> long: ...

    @property
    def reserved3(self) -> long: ...

    @property
    def reserved4(self) -> long: ...

    @property
    def reserved5(self) -> long: ...

    @property
    def reserved6(self) -> long: ...