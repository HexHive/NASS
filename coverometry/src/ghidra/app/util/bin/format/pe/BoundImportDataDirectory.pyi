from typing import List
import ghidra.app.util.bin.format.pe
import ghidra.app.util.importer
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util
import ghidra.util.task
import java.io
import java.lang


class BoundImportDataDirectory(ghidra.app.util.bin.format.pe.DataDirectory):
    """
    Points to an array of IMAGE_BOUND_IMPORT_DESCRIPTORs.
    """









    def addDescriptor(self, bid: ghidra.app.util.bin.format.pe.BoundImportDescriptor) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getBoundImportDescriptors(self) -> List[ghidra.app.util.bin.format.pe.BoundImportDescriptor]:
        """
        Returns the array of bound import descriptors defined in this bound import data directory.
        @return the array of bound import descriptors defined in this bound import data directory
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDirectoryName(self) -> unicode: ...

    def getPointer(self) -> int: ...

    def getSize(self) -> int:
        """
        Returns the size of this data directory.
        @return the size of this data directory
        """
        ...

    def getVirtualAddress(self) -> int:
        """
        Returns the relative virtual address of this data directory.
        @return the relative virtual address of this data directory
        """
        ...

    def hasParsedCorrectly(self) -> bool: ...

    def hashCode(self) -> int: ...

    def markup(self, program: ghidra.program.model.listing.Program, isBinary: bool, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog, ntHeader: ghidra.app.util.bin.format.pe.NTHeader) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parse(self) -> bool: ...

    def setSize(self, size: int) -> None:
        """
        Sets the size of this data directory.
        @param size the new size of this data directory
        """
        ...

    def setVirtualAddress(self, addr: int) -> None:
        """
        Sets the relative virtual address of this data directory.
        @param addr the new relative virtual address
        """
        ...

    def toDataType(self) -> ghidra.program.model.data.DataType:
        """
        @see ghidra.app.util.bin.StructConverter#toDataType()
        """
        ...

    def toString(self) -> unicode:
        """
        @see java.lang.Object#toString()
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeBytes(self, raf: java.io.RandomAccessFile, dc: ghidra.util.DataConverter, template: ghidra.app.util.bin.format.pe.PortableExecutable) -> None: ...

    @property
    def boundImportDescriptors(self) -> List[ghidra.app.util.bin.format.pe.BoundImportDescriptor]: ...

    @property
    def directoryName(self) -> unicode: ...