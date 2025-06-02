from typing import List
import generic.jar
import ghidra.app.plugin.core.datamgr.archive
import ghidra.framework.model
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.io
import java.lang


class DataTypeArchiveService(object):
    """
    A service that manages a set of data type archives, allowing re-use of already open
     archives.
    """









    def closeArchive(self, dtm: ghidra.program.model.data.DataTypeManager) -> None:
        """
        Closes the archive for the given {@link DataTypeManager}.  This will ignore request to 
         close the open Program's manager and the built-in manager.
        @param dtm the data type manager of the archive to close
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getBuiltInDataTypesManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Get the data type manager that has all of the built in types.
        @return data type manager for built in data types
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDataTypeManagers(self) -> List[ghidra.program.model.data.DataTypeManager]:
        """
        Gets the open data type managers.
        @return the open data type managers.
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def openArchive(self, dataTypeArchive: ghidra.program.model.listing.DataTypeArchive) -> ghidra.app.plugin.core.datamgr.archive.Archive:
        """
        A method to open an Archive for the given, pre-existing DataTypeArchive (like one that
         was opened during the import process.
        @param dataTypeArchive the archive from which to create an Archive
        @return an Archive based upon the given DataTypeArchive
        """
        ...

    @overload
    def openArchive(self, file: generic.jar.ResourceFile, acquireWriteLock: bool) -> ghidra.program.model.data.DataTypeManager:
        """
        Opens the specified gdt (file based) data type archive.
        @param file gdt file
        @param acquireWriteLock true if write lock should be acquired (i.e., open for update)
        @return the data type archive
        @throws IOException if an i/o error occurs opening the data type archive
        @throws DuplicateIdException if another archive with the same ID is already open
        """
        ...

    @overload
    def openArchive(self, file: java.io.File, acquireWriteLock: bool) -> ghidra.app.plugin.core.datamgr.archive.Archive:
        """
        A method to open an Archive for the given, pre-existing archive file (*.gdt)
        @param file data type archive file
        @param acquireWriteLock true if write lock should be acquired (i.e., open for update)
        @return an Archive based upon the given archive files
        @throws IOException if an i/o error occurs opening the data type archive
        @throws DuplicateIdException if another archive with the same ID is already open
        """
        ...

    @overload
    def openArchive(self, domainFile: ghidra.framework.model.DomainFile, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.data.DataTypeManager:
        """
        Opens the specified project-located data type archive.
        @param domainFile archive file located in the current project
        @param monitor {@link TaskMonitor} to display progess during the opening
        @return the data type archive
        @throws IOException if an i/o error occurs opening the data type archive
        @throws DuplicateIdException if another archive with the same ID is already open
        @throws VersionException
        @throws CancelledException
        """
        ...

    def openDataTypeArchive(self, archiveName: unicode) -> ghidra.program.model.data.DataTypeManager:
        """
        Opens a data type archive that was built into the Ghidra installation.
         <p>
         NOTE: This is predicated upon all archive files having a unique name within the installation.
         <p>
         Any path prefix specified may prevent the file from opening (or reopening) correctly.
        @param archiveName archive file name (i.e., "generic_C_lib")
        @return the data type archive or null if an archive with the specified name
         can not be found.
        @throws IOException if an i/o error occurs opening the data type archive
        @throws DuplicateIdException if another archive with the same ID is already open
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def builtInDataTypesManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    @property
    def dataTypeManagers(self) -> List[ghidra.program.model.data.DataTypeManager]: ...