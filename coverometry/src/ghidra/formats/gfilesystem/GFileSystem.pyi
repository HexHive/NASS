from typing import List
import ghidra.app.util.bin
import ghidra.formats.gfilesystem
import ghidra.formats.gfilesystem.fileinfo
import ghidra.util.classfinder
import ghidra.util.task
import java.io
import java.lang


class GFileSystem(java.io.Closeable, ghidra.util.classfinder.ExtensionPoint, object):
    """
    Interface that represents a filesystem that contains files.
 
     Operations take a TaskMonitor if they need to be cancel-able.
 
     Use a FileSystemService to discover and 
     open instances of filesystems in files or to open a known FSRL path or to
     deal with creating FileSystemService#createTempFile(long).
 
     NOTE:
     ALL GFileSystem sub-CLASSES MUST END IN "FileSystem". If not, the ClassSearcher
     will not find them.
 
     Also note that this interface came after the original abstract class GFileSystem and its many
     implementations, and usage is being migrated to this interface where possible and as
     time permits.
    """









    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getByteProvider(self, file: ghidra.formats.gfilesystem.GFile, monitor: ghidra.util.task.TaskMonitor) -> ghidra.app.util.bin.ByteProvider:
        """
        Returns a {@link ByteProvider} that contains the contents of the specified {@link GFile}.
         <p>
         The caller is responsible for closing the provider.
        @param file {@link GFile} to get bytes for
        @param monitor {@link TaskMonitor} to watch and update progress
        @return new {@link ByteProvider} that contains the contents of the file, or NULL if file
         doesn't have data
        @throws IOException if error
        @throws CancelledException if user cancels
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode:
        """
        Returns a description of this file system.
         <p>
         This default implementation returns the description value in {@link FileSystemInfo}
         annotation.
        @return description string
        """
        ...

    def getFSRL(self) -> ghidra.formats.gfilesystem.FSRLRoot:
        """
        File system's FSRL
        @return {@link FSRLRoot} of this filesystem.
        """
        ...

    def getFileAttributes(self, file: ghidra.formats.gfilesystem.GFile, monitor: ghidra.util.task.TaskMonitor) -> ghidra.formats.gfilesystem.fileinfo.FileAttributes:
        """
        Returns a container of {@link FileAttribute} values.
         <p>
         Implementors of this method are not required to add FSRL, NAME, or PATH values unless
         the values are non-standard.
        @param file {@link GFile} to get the attributes for
        @param monitor {@link TaskMonitor}
        @return {@link FileAttributes} instance (possibly read-only), maybe empty but never null
        """
        ...

    def getFileCount(self) -> int:
        """
        Returns the number of files in the filesystem, if known, otherwise -1 if not known.
        @return number of files in this filesystem, -1 if not known.
        """
        ...

    def getInputStream(self, file: ghidra.formats.gfilesystem.GFile, monitor: ghidra.util.task.TaskMonitor) -> java.io.InputStream:
        """
        Returns an {@link InputStream} that contains the contents of the specified {@link GFile}.
         <p>
         The caller is responsible for closing the stream.
         <p>
        @param file {@link GFile} to get an InputStream for
        @param monitor {@link TaskMonitor} to watch and update progress
        @return new {@link InputStream} contains the contents of the file or NULL if the
         file doesn't have data.
        @throws IOException if IO problem
        @throws CancelledException if user cancels.
        """
        ...

    @staticmethod
    def getInputStreamHelper(file: ghidra.formats.gfilesystem.GFile, fs: ghidra.formats.gfilesystem.GFileSystem, monitor: ghidra.util.task.TaskMonitor) -> java.io.InputStream:
        """
        Default implementation of getting an {@link InputStream} from a {@link GFile}'s
         {@link ByteProvider}.
         <p>
        @param file {@link GFile}
        @param fs the {@link GFileSystem filesystem} containing the file
        @param monitor {@link TaskMonitor} to allow canceling
        @return new {@link InputStream} containing bytes of the file
        @throws CancelledException if canceled
        @throws IOException if error
        """
        ...

    def getListing(self, directory: ghidra.formats.gfilesystem.GFile) -> List[ghidra.formats.gfilesystem.GFile]:
        """
        Returns a list of {@link GFile files} that reside in the specified directory on
         this filesystem.
         <p>
        @param directory NULL means root of filesystem.
        @return {@link List} of {@link GFile} instances of file in the requested directory.
        @throws IOException if IO problem.
        """
        ...

    def getName(self) -> unicode:
        """
        File system volume name.
         <p>
         Typically the name of the container file, or a internally stored 'volume' name.
        @return string filesystem volume name.
        """
        ...

    def getRefManager(self) -> ghidra.formats.gfilesystem.FileSystemRefManager:
        """
        Returns the {@link FileSystemRefManager ref manager} that is responsible for
         creating and releasing {@link FileSystemRef refs} to this filesystem.
         <p>
        @return {@link FileSystemRefManager} that manages references to this filesystem.
        """
        ...

    def getType(self) -> unicode:
        """
        Returns the type of this file system.
         <p>
         This default implementation returns the type value in {@link FileSystemInfo}
         annotation.
        @return type string
        """
        ...

    def hashCode(self) -> int: ...

    def isClosed(self) -> bool:
        """
        Returns true if the filesystem has been {@link #close() closed}
        @return boolean true if the filesystem has been closed.
        """
        ...

    def isStatic(self) -> bool:
        """
        Indicates if this filesystem is a static snapshot or changes.
        @return boolean true if the filesystem is static or false if dynamic content.
        """
        ...

    def lookup(self, path: unicode) -> ghidra.formats.gfilesystem.GFile:
        """
        Retrieves a {@link GFile} from this filesystem based on its full path and filename, using
         this filesystem's default name comparison logic (eg. case sensitive vs insensitive).
         <p>
        @param path string path and filename of a file located in this filesystem.  Use 
         {@code null} or "/" to retrieve the root directory
        @return {@link GFile} instance of requested file, null if not found.
        @throws IOException if IO error when looking up file.
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