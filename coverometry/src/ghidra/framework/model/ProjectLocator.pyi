import java.io
import java.lang
import java.net


class ProjectLocator(object):
    """
    Lightweight descriptor of a local Project storage location.
    """

    PROJECT_DIR_SUFFIX: unicode = u'.rep'
    PROJECT_FILE_SUFFIX: unicode = u'.gpr'



    def __init__(self, path: unicode, name: unicode):
        """
        Construct a project locator object.
        @param path path to parent directory (may or may not exist).  The user's temp directory
         will be used if this value is null or blank.
         WARNING: Use of a relative paths should be avoided (e.g., on a windows platform
         an absolute path should start with a drive letter specification such as C:\path,
         while this same path on a Linux platform would be treated as relative).
        @param name name of the project
        """
        ...



    def equals(self, obj: object) -> bool: ...

    def exists(self) -> bool:
        """
        Returns true if project storage exists
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getLocation(self) -> unicode:
        """
        Get the location of the project which will contain marker file
         ({@link #getMarkerFile()}) and project directory ({@link #getProjectDir()}). 
         Note: directory may or may not exist.
        @return project location directory
        """
        ...

    def getMarkerFile(self) -> java.io.File:
        """
        Returns the file that indicates a Ghidra project.
        """
        ...

    def getName(self) -> unicode:
        """
        Get the name of the project identified by this project info.
        """
        ...

    def getProjectDir(self) -> java.io.File:
        """
        Returns the project directory
        """
        ...

    @staticmethod
    def getProjectDirExtension() -> unicode:
        """
        Returns the project directory file extension.
        """
        ...

    @staticmethod
    def getProjectExtension() -> unicode:
        """
        Returns the file extension suitable for creating file filters for the file chooser.
        """
        ...

    def getProjectLockFile(self) -> java.io.File:
        """
        Returns project lock file to prevent multiple accesses to the
         same project at once.
        """
        ...

    def getURL(self) -> java.net.URL:
        """
        Returns the URL associated with this local project.  If using a temporary transient
         project location this URL should not be used.
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isProjectDir(file: java.io.File) -> bool:
        """
        Returns whether the given file is a project directory.
        @param file file to check
        @return true if the file is a project directory
        """
        ...

    def isTransient(self) -> bool:
        """
        Returns true if this project URL corresponds to a transient project
         (e.g., corresponds to remote Ghidra URL)
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
    def URL(self) -> java.net.URL: ...

    @property
    def location(self) -> unicode: ...

    @property
    def markerFile(self) -> java.io.File: ...

    @property
    def name(self) -> unicode: ...

    @property
    def projectDir(self) -> java.io.File: ...

    @property
    def projectLockFile(self) -> java.io.File: ...

    @property
    def transient(self) -> bool: ...