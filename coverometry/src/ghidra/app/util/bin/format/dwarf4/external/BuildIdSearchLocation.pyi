import ghidra.app.util.bin.format.dwarf4.external
import ghidra.formats.gfilesystem
import ghidra.util.task
import java.lang


class BuildIdSearchLocation(object, ghidra.app.util.bin.format.dwarf4.external.SearchLocation):
    """
    A SearchLocation that expects the external debug files to be named using the hexadecimal
     value of the hash of the file, and to be arranged in a bucketed directory hierarchy using the
     first 2 hexdigits of the hash.
 
     For example, the debug file with hash  would
     be stored as "6a/ddc39dc19c1b45f9ba70baf7fd81ea6508ea7f.debug" (under some root directory).
    """





    def __init__(self, rootDir: java.io.File):
        """
        Creates a new {@link BuildIdSearchLocation} at the specified location.
        @param rootDir path to the root directory of the build-id directory (typically ends with
         "./build-id")
        """
        ...



    @staticmethod
    def create(locString: unicode, context: ghidra.app.util.bin.format.dwarf4.external.SearchLocationCreatorContext) -> ghidra.app.util.bin.format.dwarf4.external.BuildIdSearchLocation:
        """
        Creates a new {@link BuildIdSearchLocation} instance using the specified location string.
        @param locString string, earlier returned from {@link #getName()}
        @param context {@link SearchLocationCreatorContext} to allow accessing information outside
         of the location string that might be needed to create a new instance
        @return new {@link BuildIdSearchLocation} instance
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def findDebugFile(self, debugInfo: ghidra.app.util.bin.format.dwarf4.external.ExternalDebugInfo, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.FSRL: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescriptiveName(self) -> unicode: ...

    def getName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isBuildIdSearchLocation(locString: unicode) -> bool:
        """
        Returns true if the specified location string specifies a BuildIdSearchLocation.
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