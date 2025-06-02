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


class SegmentCommand(ghidra.app.util.bin.format.macho.commands.LoadCommand):
    """
    Represents a segment_command and segment_command_64 structure
    """





    def __init__(self, reader: ghidra.app.util.bin.BinaryReader, is32bit: bool): ...



    def contains(self, addr: long) -> bool:
        """
        Returns true if the segment contains the given address
        @param addr The address to check
        @return True if the segment contains the given address; otherwise, false
        """
        ...

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

    def getFileOffset(self) -> long: ...

    def getFileSize(self) -> long: ...

    def getFlags(self) -> int: ...

    def getInitProtection(self) -> int:
        """
        Returns a octal model value reflecting the
         segment's initial protection value.
         For example:{@code
         7 -> 0x111 -> rwx
         5 -> 0x101 -> rx}
        @return the initial protections of a segment
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

    def getMaxProtection(self) -> int:
        """
        Returns a octal model value reflecting the
         segment's maximum protection value allowed.
         For example:{@code
         7 -> 0x111 -> rwx
         5 -> 0x101 -> rx}
        @return the maximum protections of a segment
        """
        ...

    def getNumberOfSections(self) -> int: ...

    def getSectionByName(self, sectionName: unicode) -> ghidra.app.util.bin.format.macho.Section: ...

    def getSectionContaining(self, address: ghidra.program.model.address.Address) -> ghidra.app.util.bin.format.macho.Section: ...

    def getSections(self) -> List[ghidra.app.util.bin.format.macho.Section]: ...

    def getSegmentName(self) -> unicode: ...

    def getStartIndex(self) -> long:
        """
        Returns the binary start index of this load command
        @return the binary start index of this load command
        """
        ...

    def getVMaddress(self) -> long: ...

    def getVMsize(self) -> long: ...

    def hashCode(self) -> int: ...

    def isAppleProtected(self) -> bool: ...

    def isExecute(self) -> bool:
        """
        Returns true if the initial protections include EXECUTE.
        @return true if the initial protections include EXECUTE
        """
        ...

    def isRead(self) -> bool:
        """
        Returns true if the initial protections include READ.
        @return true if the initial protections include READ
        """
        ...

    def isWrite(self) -> bool:
        """
        Returns true if the initial protections include WRITE.
        @return true if the initial protections include WRITE
        """
        ...

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

    def setFileOffset(self, fileOffset: long) -> None: ...

    def setFileSize(self, fileSize: long) -> None: ...

    def setVMaddress(self, vmaddr: long) -> None: ...

    def setVMsize(self, vmSize: long) -> None: ...

    def toDataType(self) -> ghidra.program.model.data.DataType: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def VMaddress(self) -> long: ...

    @VMaddress.setter
    def VMaddress(self, value: long) -> None: ...

    @property
    def VMsize(self) -> long: ...

    @VMsize.setter
    def VMsize(self, value: long) -> None: ...

    @property
    def appleProtected(self) -> bool: ...

    @property
    def commandName(self) -> unicode: ...

    @property
    def execute(self) -> bool: ...

    @property
    def fileOffset(self) -> long: ...

    @fileOffset.setter
    def fileOffset(self, value: long) -> None: ...

    @property
    def fileSize(self) -> long: ...

    @fileSize.setter
    def fileSize(self, value: long) -> None: ...

    @property
    def flags(self) -> int: ...

    @property
    def initProtection(self) -> int: ...

    @property
    def maxProtection(self) -> int: ...

    @property
    def numberOfSections(self) -> int: ...

    @property
    def read(self) -> bool: ...

    @property
    def sections(self) -> List[object]: ...

    @property
    def segmentName(self) -> unicode: ...

    @property
    def write(self) -> bool: ...