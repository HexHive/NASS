from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import ghidra.formats.gfilesystem.fileinfo
import ghidra.util.task
import java.io
import java.lang
import java.util


class LocalFileSystem(object, ghidra.formats.gfilesystem.GFileSystem, ghidra.formats.gfilesystem.GFileHashProvider):
    """
    A GFileSystem implementation giving access to the user's operating system's
     local file system.
 
     This implementation does not have a GFileSystemFactory as
     this class will be used as the single root filesystem.
 
     Closing() this filesystem does nothing.
    """

    FSTYPE: unicode = u'file'







    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getByteProvider(self, file: ghidra.formats.gfilesystem.GFile, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getFSRL(self) -> ghidra.formats.gfilesystem.FSRLRoot: ...

    @overload
    def getFileAttributes(self, f: java.io.File) -> ghidra.formats.gfilesystem.fileinfo.FileAttributes:
        """
        Create a {@link FileAttributes} container with info about the specified local file.
        @param f {@link File} to query
        @return {@link FileAttributes} instance
        """
        ...

    @overload
    def getFileAttributes(self, file: ghidra.formats.gfilesystem.GFile, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.fileinfo.FileAttributes: ...

    def getFileCount(self) -> int: ...

    def getInputStream(self, file: ghidra.formats.gfilesystem.GFile, monitor: ghidra.util.task.TaskMonitor) -> java.io.InputStream: ...

    @staticmethod
    def getInputStreamHelper(__a0: ghidra.formats.gfilesystem.GFile, __a1: ghidra.formats.gfilesystem.GFileSystem, __a2: ghidra.util.task.TaskMonitor) -> java.io.InputStream: ...

    def getListing(self, directory: ghidra.formats.gfilesystem.GFile) -> List[ghidra.formats.gfilesystem.GFile]: ...

    def getLocalFSRL(self, f: java.io.File) -> ghidra.formats.gfilesystem.FSRL:
        """
        Converts a {@link File} into a {@link FSRL}.
         <p>
         NOTE: The given {@link File}'s absolute path will be used.
        @param f The {@link File} to convert to an {@link FSRL}
        @return The {@link FSRL}
        """
        ...

    def getLocalFile(self, fsrl: ghidra.formats.gfilesystem.FSRL) -> java.io.File:
        """
        Convert a FSRL that points to this file system into a java {@link File}.
        @param fsrl {@link FSRL}
        @return {@link File}
        @throws IOException if FSRL does not point to this file system
        """
        ...

    def getMD5Hash(self, file: ghidra.formats.gfilesystem.GFile, required: bool, monitor: ghidra.util.task.TaskMonitor) -> unicode: ...

    def getName(self) -> unicode: ...

    def getRefManager(self) -> ghidra.formats.gfilesystem.FileSystemRefManager: ...

    def getSubFileSystem(self, fsrl: ghidra.formats.gfilesystem.FSRL) -> ghidra.formats.gfilesystem.LocalFileSystemSub:
        """
        Creates a new file system instance that is a sub-view limited to the specified directory.
        @param fsrl {@link FSRL} that must be a directory in this local filesystem
        @return new {@link LocalFileSystemSub} instance
        @throws IOException if bad FSRL
        """
        ...

    def getType(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isClosed(self) -> bool: ...

    def isLocalSubdir(self, fsrl: ghidra.formats.gfilesystem.FSRL) -> bool:
        """
        Returns true if the {@link FSRL} is a local filesystem subdirectory.
        @param fsrl {@link FSRL} to test.
        @return boolean true if local filesystem directory.
        """
        ...

    def isStatic(self) -> bool: ...

    def lookup(self, path: unicode) -> ghidra.formats.gfilesystem.GFile: ...

    @staticmethod
    def lookupFile(baseDir: java.io.File, path: unicode, nameComp: java.util.Comparator) -> java.io.File:
        """
        Looks up a file, by its string path, using a custom comparator.
         <p>
         If any element of the path, or the filename are not found, returns a null.
         <p>
         A null custom comparator avoids testing each element of the directory path and instead
         relies on the native local file system's name matching.
        @param baseDir optional directory to start lookup at
        @param path String path
        @param nameComp optional {@link Comparator} that will compare filenames, or {@code null} 
         to use native local file system lookup (eg. case-insensitive on windows)
        @return File that points to the requested path, or null if file was not present on the
         local filesystem (because it doesn't exist, or the name comparison function rejected it)
        """
        ...

    @staticmethod
    def makeGlobalRootFS() -> ghidra.formats.gfilesystem.LocalFileSystem:
        """
        Create a new instance
        @return new {@link LocalFileSystem} instance using {@link #FSTYPE} as its FSRL type.
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
    def FSRL(self) -> ghidra.formats.gfilesystem.FSRLRoot: ...

    @property
    def closed(self) -> bool: ...

    @property
    def description(self) -> unicode: ...

    @property
    def fileCount(self) -> int: ...

    @property
    def name(self) -> unicode: ...

    @property
    def refManager(self) -> ghidra.formats.gfilesystem.FileSystemRefManager: ...

    @property
    def static(self) -> bool: ...

    @property
    def type(self) -> unicode: ...