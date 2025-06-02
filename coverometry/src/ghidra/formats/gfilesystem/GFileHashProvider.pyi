import ghidra.formats.gfilesystem
import ghidra.util.task
import java.lang


class GFileHashProvider(object):
    """
    GFileSystem add-on interface that provides MD5 hashing for file located within the filesystem
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getMD5Hash(self, file: ghidra.formats.gfilesystem.GFile, required: bool, monitor: ghidra.util.task.TaskMonitor) -> unicode:
        """
        Returns the MD5 hash of the specified file.
        @param file the {@link GFile}
        @param required boolean flag, if true the hash will always be returned, even if it has to
         be calculated.  If false, the hash will be returned if easily available
        @param monitor {@link TaskMonitor}
        @return MD5 hash as a string
        @throws CancelledException if cancelled
        @throws IOException if error
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

