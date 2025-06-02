import ghidra.app.util.bin.format.dwarf4.external
import ghidra.formats.gfilesystem
import ghidra.util.task
import java.lang


class SearchLocation(object):
    """
    Represents a collection of dwarf external debug files that can be searched.
    """









    def equals(self, __a0: object) -> bool: ...

    def findDebugFile(self, debugInfo: ghidra.app.util.bin.format.dwarf4.external.ExternalDebugInfo, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.FSRL:
        """
        Searchs for a debug file that fulfills the criteria specified in the {@link ExternalDebugInfo}.
        @param debugInfo search criteria
        @param monitor {@link TaskMonitor}
        @return {@link FSRL} of the matching file, or {@code null} if not found
        @throws IOException if error
        @throws CancelledException if cancelled
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDescriptiveName(self) -> unicode:
        """
        Returns a human formatted string describing this location, used in UI prompts or lists.
        @return formatted string
        """
        ...

    def getName(self) -> unicode:
        """
        Returns the name of this instance, which should be a serialized copy of this instance.
        @return String serialized data of this instance, typically in "something://serialized_data"
         form
        """
        ...

    def hashCode(self) -> int: ...

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