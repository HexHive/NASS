import ghidra.app.util.bin.format.dwarf4.external
import ghidra.formats.gfilesystem
import ghidra.util.task
import java.lang


class SameDirSearchLocation(object, ghidra.app.util.bin.format.dwarf4.external.SearchLocation):
    """
    A SearchLocation that only looks in the program's original import directory.
    """





    def __init__(self, progDir: java.io.File):
        """
        Creates a new {@link SameDirSearchLocation} at the specified location.
        @param progDir path to the program's import directory
        """
        ...



    @staticmethod
    def create(locString: unicode, context: ghidra.app.util.bin.format.dwarf4.external.SearchLocationCreatorContext) -> ghidra.app.util.bin.format.dwarf4.external.SameDirSearchLocation:
        """
        Creates a new {@link SameDirSearchLocation} instance using the current program's
         import location.
        @param locString unused
        @param context {@link SearchLocationCreatorContext}
        @return new {@link SameDirSearchLocation} instance
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def findDebugFile(self, debugInfo: ghidra.app.util.bin.format.dwarf4.external.ExternalDebugInfo, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.FSRL: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescriptiveName(self) -> unicode: ...

    def getName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isSameDirSearchLocation(locString: unicode) -> bool:
        """
        Returns true if the specified location string specifies a SameDirSearchLocation.
        @param locString string to test
        @return boolean true if locString specifies a BuildId location
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