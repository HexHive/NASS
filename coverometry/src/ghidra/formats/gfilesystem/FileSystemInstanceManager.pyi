import ghidra.formats.gfilesystem
import java.lang


class FileSystemInstanceManager(object, ghidra.formats.gfilesystem.FileSystemEventListener):
    """
    A threadsafe cache of GFileSystem instances (organized by their FSRLRoot)
 
     Any filesystems that are not referenced by outside users (via a FileSystemRef) will
     be closed and removed from the cache when the next #cacheMaint() is performed.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def onFilesystemClose(self, fs: ghidra.formats.gfilesystem.GFileSystem) -> None: ...

    def onFilesystemRefChange(self, fs: ghidra.formats.gfilesystem.GFileSystem, refManager: ghidra.formats.gfilesystem.FileSystemRefManager) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

