from typing import List
import ghidra.app.util.bin.format.macho
import ghidra.app.util.bin.format.macho.commands
import ghidra.app.util.importer
import ghidra.program.flatapi
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class SymbolTableCommand(ghidra.app.util.bin.format.macho.commands.LoadCommand):
    """
    Represents a symtab_command structure
    """





    def __init__(self, loadCommandReader: ghidra.app.util.bin.BinaryReader, dataReader: ghidra.app.util.bin.BinaryReader, header: ghidra.app.util.bin.format.macho.MachHeader):
        """
        Creates and parses a new {@link SymbolTableCommand}
        @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
           command
        @param dataReader A {@link BinaryReader reader} that can read the data that the load command
           references.  Note that this might be in a different underlying provider.
        @param header The {@link MachHeader header} associated with this load command
        @throws IOException if an IO-related error occurs while parsing
        """
        ...



    def addSymbols(self, __a0: List[object]) -> None: ...

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

    def getNumberOfSymbols(self) -> int:
        """
        An integer indicating the number of entries in the symbol table.
        @return the number of entries in the symbol table
        """
        ...

    def getStartIndex(self) -> long:
        """
        Returns the binary start index of this load command
        @return the binary start index of this load command
        """
        ...

    def getStringTableOffset(self) -> int:
        """
        An integer containing the byte offset from the start of the image to the
         location of the string table.
        @return string table offset
        """
        ...

    def getStringTableSize(self) -> int:
        """
        An integer indicating the size (in bytes) of the string table.
        @return string table size in bytes
        """
        ...

    def getSymbolAt(self, index: int) -> ghidra.app.util.bin.format.macho.commands.NList: ...

    def getSymbolOffset(self) -> int:
        """
        An integer containing the byte offset from the start
         of the file to the location of the symbol table entries.
         The symbol table is an array of nlist data structures.
        @return symbol table offset
        """
        ...

    def getSymbols(self) -> List[ghidra.app.util.bin.format.macho.commands.NList]: ...

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
    def commandName(self) -> unicode: ...

    @property
    def linkerDataOffset(self) -> int: ...

    @property
    def linkerDataSize(self) -> int: ...

    @property
    def numberOfSymbols(self) -> int: ...

    @property
    def stringTableOffset(self) -> int: ...

    @property
    def stringTableSize(self) -> int: ...

    @property
    def symbolOffset(self) -> int: ...

    @property
    def symbols(self) -> List[object]: ...