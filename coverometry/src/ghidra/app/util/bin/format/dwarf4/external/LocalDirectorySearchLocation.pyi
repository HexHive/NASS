import ghidra.app.util.bin.format.dwarf4.external
import ghidra.formats.gfilesystem
import ghidra.util.task
import java.io
import java.lang


class LocalDirectorySearchLocation(object, ghidra.app.util.bin.format.dwarf4.external.SearchLocation):
    """
    A SearchLocation that recursively searches for dwarf external debug files 
     under a configured directory.
    """





    def __init__(self, searchDir: java.io.File):
        """
        Creates a new {@link LocalDirectorySearchLocation} at the specified location.
        @param searchDir path to the root directory of where to search
        """
        ...



    @staticmethod
    def calcCRC(f: java.io.File) -> int:
        """
        Calculates the crc32 for the specified file.
        @param f {@link File} to read
        @return int crc32
        @throws IOException if error reading file
        """
        ...

    @staticmethod
    def create(locString: unicode, context: ghidra.app.util.bin.format.dwarf4.external.SearchLocationCreatorContext) -> ghidra.app.util.bin.format.dwarf4.external.LocalDirectorySearchLocation:
        """
        Creates a new {@link LocalDirectorySearchLocation} instance using the specified location string.
        @param locString string, earlier returned from {@link #getName()}
        @param context {@link SearchLocationCreatorContext} to allow accessing information outside
         of the location string that might be needed to create a new instance
        @return new {@link LocalDirectorySearchLocation} instance
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def findDebugFile(self, debugInfo: ghidra.app.util.bin.format.dwarf4.external.ExternalDebugInfo, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.FSRL: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescriptiveName(self) -> unicode: ...

    def getName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isLocalDirSearchLoc(locString: unicode) -> bool:
        """
        Returns true if the specified location string specifies a LocalDirectorySearchLocation.
        @param locString string to test
        @return boolean true if locString specifies a local dir search location
        """
        ...

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
    def descriptiveName(self) -> unicode: ...

    @property
    def name(self) -> unicode: ...