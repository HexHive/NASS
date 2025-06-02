from typing import List
import ghidra.framework.client
import ghidra.framework.data
import ghidra.framework.model
import ghidra.framework.remote
import ghidra.framework.store
import ghidra.util.task
import java.io
import java.lang
import java.net
import java.util


class DefaultProjectData(object, ghidra.framework.model.ProjectData):
    """
    Helper class to manage files within a project.
    """

    INDEXED_DATA_FOLDER_NAME: unicode = u'idata'
    MANGLED_DATA_FOLDER_NAME: unicode = u'data'
    OWNER: unicode = u'OWNER'
    PORT_NUMBER: unicode = u'PORT_NUMBER'
    REPOSITORY_NAME: unicode = u'REPOSITORY_NAME'
    SERVER_NAME: unicode = u'SERVER'
    USER_FOLDER_NAME: unicode = u'user'
    VERSIONED_FOLDER_NAME: unicode = u'versioned'



    @overload
    def __init__(self, localStorageLocator: ghidra.framework.model.ProjectLocator, isInWritableProject: bool, resetOwner: bool):
        """
        Constructor for existing projects.
        @param localStorageLocator the location of the project
        @param isInWritableProject true if project content is writable, false if project is read-only
        @param resetOwner true to reset the project owner
        @throws IOException if an i/o error occurs
        @throws NotOwnerException if inProject is true and user is not owner
        @throws LockException if {@code isInWritableProject} is true and unable to establish project 
         write lock (i.e., project in-use)
        @throws FileNotFoundException if project directory not found
        """
        ...

    @overload
    def __init__(self, localStorageLocator: ghidra.framework.model.ProjectLocator, repository: ghidra.framework.client.RepositoryAdapter, isInWritableProject: bool):
        """
        Constructor for a new project.
        @param localStorageLocator the location of the project
        @param repository a repository if this is a shared project or null if it is a private project
        @param isInWritableProject true if project content is writable, false if project is read-only
        @throws IOException if an i/o error occurs
        @throws LockException if {@code isInWritableProject} is true and unable to establish project 
         lock (i.e., project in-use)
        """
        ...



    def addDomainFolderChangeListener(self, l: ghidra.framework.model.DomainFolderChangeListener) -> None: ...

    def close(self) -> None: ...

    def convertProjectToShared(self, newRepository: ghidra.framework.client.RepositoryAdapter, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def findCheckedOutFiles(self, monitor: ghidra.util.task.TaskMonitor) -> List[ghidra.framework.model.DomainFile]:
        """
        Find all project files which are currently checked-out
        @param monitor task monitor (no progress updates)
        @return list of current checkout files
        @throws IOException if IO error occurs
        @throws CancelledException if task cancelled
        """
        ...

    def findOpenFiles(self, __a0: List[object]) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def getFile(self, path: unicode) -> ghidra.framework.model.DomainFile: ...

    def getFileByID(self, fileID: unicode) -> ghidra.framework.model.DomainFile: ...

    def getFileCount(self) -> int: ...

    def getFolder(self, path: unicode) -> ghidra.framework.model.DomainFolder: ...

    def getLocalProjectURL(self) -> java.net.URL: ...

    def getLocalStorageClass(self) -> java.lang.Class: ...

    def getMaxNameLength(self) -> int: ...

    def getOwner(self) -> unicode:
        """
        Returns the owner of the project that is associated with this 
         DefaultProjectData.  A value of null indicates an old multiuser
         project.
        @return the owner of the project
        """
        ...

    def getPrivateFileSystem(self) -> ghidra.framework.store.FileSystem: ...

    def getProjectDir(self) -> java.io.File: ...

    def getProjectDisposalMonitor(self) -> ghidra.util.task.TaskMonitor:
        """
        Get monitor which will be cancelled if project is closed
        @return cancel monitor
        """
        ...

    def getProjectLocator(self) -> ghidra.framework.model.ProjectLocator: ...

    def getRepository(self) -> ghidra.framework.client.RepositoryAdapter: ...

    def getRootFolder(self) -> ghidra.framework.data.GhidraFolder: ...

    def getSharedProjectURL(self) -> java.net.URL: ...

    def getUser(self) -> ghidra.framework.remote.User: ...

    @staticmethod
    def getUserDataFilename(associatedFileID: unicode) -> unicode:
        """
        Returns the standard user data filename associated with the specified file ID.
        @param associatedFileID the file id
        @return user data filename
        """
        ...

    def hasInvalidCheckouts(self, __a0: List[object], __a1: ghidra.framework.client.RepositoryAdapter, __a2: ghidra.util.task.TaskMonitor) -> bool: ...

    def hashCode(self) -> int: ...

    def isClosed(self) -> bool: ...

    def isDisposed(self) -> bool: ...

    @staticmethod
    def isLocked(locator: ghidra.framework.model.ProjectLocator) -> bool:
        """
        Determine if the specified project location currently has a write lock.
        @param locator project storage locator
        @return true if project data current has write-lock else false
        """
        ...

    def makeValidName(self, name: unicode) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def readProjectProperties(projectDir: java.io.File) -> java.util.Properties:
        """
        Read the contents of the project properties file to include the following values if relavent:
         {@value #OWNER}, {@value #SERVER_NAME}, {@value #REPOSITORY_NAME}, {@value #PORT_NUMBER}
        @param projectDir project directory (*.rep)
        @return project properties or null if invalid project directory specified
        """
        ...

    def refresh(self, force: bool) -> None: ...

    def releaseDomainFiles(self, consumer: object) -> None: ...

    def removeDomainFolderChangeListener(self, l: ghidra.framework.model.DomainFolderChangeListener) -> None: ...

    def removeFromIndex(self, fileID: unicode) -> None:
        """
        Remove specified fileID from index.
        @param fileID the file ID
        """
        ...

    def testValidName(self, name: unicode, isPath: bool) -> None: ...

    def toString(self) -> unicode: ...

    def updateFileIndex(self, fileData: ghidra.framework.data.GhidraFileData) -> None:
        """
        Update the file index for the specified file data
        @param fileData file data
        """
        ...

    def updateRepositoryInfo(self, newRepository: ghidra.framework.client.RepositoryAdapter, force: bool, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def closed(self) -> bool: ...

    @property
    def disposed(self) -> bool: ...

    @property
    def fileCount(self) -> int: ...

    @property
    def localProjectURL(self) -> java.net.URL: ...

    @property
    def localStorageClass(self) -> java.lang.Class: ...

    @property
    def maxNameLength(self) -> int: ...

    @property
    def owner(self) -> unicode: ...

    @property
    def privateFileSystem(self) -> ghidra.framework.store.FileSystem: ...

    @property
    def projectDir(self) -> java.io.File: ...

    @property
    def projectDisposalMonitor(self) -> ghidra.util.task.TaskMonitor: ...

    @property
    def projectLocator(self) -> ghidra.framework.model.ProjectLocator: ...

    @property
    def repository(self) -> ghidra.framework.client.RepositoryAdapter: ...

    @property
    def rootFolder(self) -> ghidra.framework.data.GhidraFolder: ...

    @property
    def sharedProjectURL(self) -> java.net.URL: ...

    @property
    def user(self) -> ghidra.framework.remote.User: ...