import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.commands
import ghidra.app.util.bin.format.macho.commands.dyld
import ghidra.app.util.importer
import ghidra.program.flatapi
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class DyldInfoCommand(ghidra.app.util.bin.format.macho.commands.LoadCommand):
    """
    Represents a dyld_info_command structure
    """









    def equals(self, __a0: object) -> bool: ...

    def getBindOffset(self) -> int:
        """
        {@return The bind info offset}
        """
        ...

    def getBindSize(self) -> int:
        """
        {@return The bind info size}
        """
        ...

    def getBindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable:
        """
        {@return The binding table}
        """
        ...

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

    def getExportOffset(self) -> int:
        """
        {@return The export info offset}
        """
        ...

    def getExportSize(self) -> int:
        """
        {@return The export info size}
        """
        ...

    def getExportTrie(self) -> ghidra.app.util.bin.format.macho.commands.ExportTrie:
        """
        {@return The export trie}
        """
        ...

    def getLazyBindOffset(self) -> int:
        """
        {@return The lazy bind info offset}
        """
        ...

    def getLazyBindSize(self) -> int:
        """
        {@return The lazy bind info size}
        """
        ...

    def getLazyBindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable:
        """
        {@return The lazy binding table}
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

    def getRebaseOffset(self) -> int:
        """
        {@return The rebase info offset}
        """
        ...

    def getRebaseSize(self) -> int:
        """
        {@return The rebase info size}
        """
        ...

    def getStartIndex(self) -> long:
        """
        Returns the binary start index of this load command
        @return the binary start index of this load command
        """
        ...

    def getWeakBindOffset(self) -> int:
        """
        {@return The weak bind info offset}
        """
        ...

    def getWeakBindSize(self) -> int:
        """
        {@return The weak bind info size}
        """
        ...

    def getWeakBindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable:
        """
        {@return The weak binding table}
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

    @property
    def bindOffset(self) -> int: ...

    @property
    def bindSize(self) -> int: ...

    @property
    def bindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable: ...

    @property
    def commandName(self) -> unicode: ...

    @property
    def exportOffset(self) -> int: ...

    @property
    def exportSize(self) -> int: ...

    @property
    def exportTrie(self) -> ghidra.app.util.bin.format.macho.commands.ExportTrie: ...

    @property
    def lazyBindOffset(self) -> int: ...

    @property
    def lazyBindSize(self) -> int: ...

    @property
    def lazyBindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable: ...

    @property
    def rebaseOffset(self) -> int: ...

    @property
    def rebaseSize(self) -> int: ...

    @property
    def weakBindOffset(self) -> int: ...

    @property
    def weakBindSize(self) -> int: ...

    @property
    def weakBindingTable(self) -> ghidra.app.util.bin.format.macho.commands.dyld.BindingTable: ...