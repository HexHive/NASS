from typing import List
import ghidra.formats.gfilesystem
import java.lang
import java.util


class FileSystemIndexHelper(object):
    """
    A helper class used by GFilesystem implementors to track mappings between GFile
     instances and the underlying container filesystem's native file objects.
 
     Threadsafe (methods are synchronized).
 
     This class also provides filename 'unique-ifying' (per directory) where an auto-incrementing
     number will be added to a file's filename if it is not unique in the directory.
 
    """





    def __init__(self, fs: ghidra.formats.gfilesystem.GFileSystem, fsFSRL: ghidra.formats.gfilesystem.FSRLRoot):
        """
        Creates a new {@link FileSystemIndexHelper} for the specified {@link GFileSystem}.
         <p>
         A "root" directory GFile will be auto-created for the filesystem.
         <p>
        @param fs the {@link GFileSystem} that this index will be for.
        @param fsFSRL the {@link FSRLRoot fsrl} of the filesystem itself.
         (this parameter is explicitly passed here so there is no possibility of trying to call
         back to the fs's {@link GFileSystem#getFSRL()} on a half-constructed filesystem.)
        """
        ...



    def clear(self) -> None:
        """
        Removes all file info from this index.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFileByIndex(self, fileIndex: long) -> ghidra.formats.gfilesystem.GFile:
        """
        Gets the GFile instance that was associated with the filesystem file index.
        @param fileIndex index of the file in its filesystem
        @return the associated GFile instance, or null if not found
        """
        ...

    def getFileCount(self) -> int:
        """
        Number of files in this index.
        @return number of file in this index
        """
        ...

    def getListing(self, directory: ghidra.formats.gfilesystem.GFile) -> List[ghidra.formats.gfilesystem.GFile]:
        """
        Mirror's {@link GFileSystem#getListing(GFile)} interface.
        @param directory {@link GFile} directory to get the list of child files that have been
         added to this index, null means root directory
        @return {@link List} of GFile files that are in the specified directory, never null
        """
        ...

    def getMetadata(self, f: ghidra.formats.gfilesystem.GFile) -> METADATATYPE:
        """
        Gets the opaque filesystem specific blob that was associated with the specified file.
        @param f {@link GFile} to look for
        @return Filesystem specific blob associated with the specified file, or null if not found
        """
        ...

    def getRootDir(self) -> ghidra.formats.gfilesystem.GFile:
        """
        Gets the root {@link GFile} object for this filesystem index.
        @return root {@link GFile} object.
        """
        ...

    def hashCode(self) -> int: ...

    @overload
    def lookup(self, path: unicode) -> ghidra.formats.gfilesystem.GFile:
        """
        Mirror's {@link GFileSystem#lookup(String)} interface.
        @param path path and filename of a file to find
        @return {@link GFile} instance or null if no file was added to the index at that path
        """
        ...

    @overload
    def lookup(self, baseDir: ghidra.formats.gfilesystem.GFile, path: unicode, nameComp: java.util.Comparator) -> ghidra.formats.gfilesystem.GFile:
        """
        Mirror's {@link GFileSystem#lookup(String)} interface, with additional parameters to
         control the lookup.
        @param baseDir optional starting directory to perform lookup
        @param path path and filename of a file to find
        @param nameComp optional {@link Comparator} that compares file names.  Suggested values are 
         {@code String::compareTo} or {@code String::compareToIgnoreCase} or {@code null} (also exact).
        @return {@link GFile} instance or null if no file was added to the index at that path
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setMetadata(self, __a0: ghidra.formats.gfilesystem.GFile, __a1: object) -> None: ...

    def storeFile(self, __a0: unicode, __a1: long, __a2: bool, __a3: long, __a4: object) -> ghidra.formats.gfilesystem.GFile: ...

    def storeFileWithParent(self, __a0: unicode, __a1: ghidra.formats.gfilesystem.GFile, __a2: long, __a3: bool, __a4: long, __a5: object) -> ghidra.formats.gfilesystem.GFile: ...

    def toString(self) -> unicode: ...

    def updateFSRL(self, file: ghidra.formats.gfilesystem.GFile, newFSRL: ghidra.formats.gfilesystem.FSRL) -> None:
        """
        Updates the FSRL of a file already in the index.
        @param file current {@link GFile}
        @param newFSRL the new FSRL the new file will be given
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def fileCount(self) -> int: ...

    @property
    def rootDir(self) -> ghidra.formats.gfilesystem.GFile: ...