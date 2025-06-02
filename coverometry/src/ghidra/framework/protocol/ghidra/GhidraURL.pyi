import ghidra.framework.model
import java.lang
import java.net


class GhidraURL(object):
    """
    Supported URL forms include:
 
 
 
 
    """

    MARKER_FILE_EXTENSION: unicode = u'.gpr'
    PROJECT_DIRECTORY_EXTENSION: unicode = u'.rep'
    PROTOCOL: unicode = u'ghidra'







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getDisplayString(url: java.net.URL) -> unicode:
        """
        Generate preferred display string for Ghidra URLs.
         Form can be parsed by the toURL method.
        @param url ghidra URL
        @return formatted URL display string
        @see #toURL(String)
        """
        ...

    @staticmethod
    def getNormalizedURL(url: java.net.URL) -> java.net.URL:
        """
        Get a normalized URL which eliminates use of host names and optional URL ref
         which may prevent direct comparison.
        @param url ghidra URL
        @return normalized url
        """
        ...

    @staticmethod
    def getProjectPathname(ghidraUrl: java.net.URL) -> unicode:
        """
        Get the project pathname referenced by the specified Ghidra file/folder URL.
         If path is missing root folder is returned.
        @param ghidraUrl ghidra file/folder URL (server-only URL not permitted)
        @return pathname of file or folder
        """
        ...

    @staticmethod
    def getProjectStorageLocator(localProjectURL: java.net.URL) -> ghidra.framework.model.ProjectLocator:
        """
        Get the project locator which corresponds to the specified local project URL.
         Confirm local project URL with {@link #isLocalProjectURL(URL)} prior to method use.
        @param localProjectURL local Ghidra project URL
        @return project locator or null if invalid path specified
        @throws IllegalArgumentException URL is not a valid local project URL
        """
        ...

    @staticmethod
    def getProjectURL(ghidraUrl: java.net.URL) -> java.net.URL:
        """
        Get normalized URL which corresponds to the local-project or repository
        @param ghidraUrl ghidra file/folder URL (server-only URL not permitted)
        @return local-project or repository URL
        """
        ...

    @staticmethod
    def getRepositoryName(url: java.net.URL) -> unicode:
        """
        Get the shared repository name associated with a repository URL or null
         if not applicable.  For ghidra URL extensions it is assumed that the first path element
         corresponds to the repository name.
        @param url ghidra URL for shared project resource
        @return repository name or null if not applicable to URL
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isGhidraURL(str: unicode) -> bool:
        """
        Determine if the specified string appears to be a possible ghidra URL
         (starts with "ghidra:/").
        @param str string to be checked
        @return true if string is possible ghidra URL
        """
        ...

    @staticmethod
    def isLocalProjectURL(url: java.net.URL) -> bool:
        """
        Determine if the specified URL is a local project URL.
         No checking is performed as to the existence of the project.
        @param url ghidra URL
        @return true if specified URL refers to a local 
         project (ghidra:/path/projectName...)
        """
        ...

    @staticmethod
    def isServerRepositoryURL(url: java.net.URL) -> bool:
        """
        Determine if the specified URL is any type of server "repository" URL.
         No checking is performed as to the existence of the server or repository.
         NOTE: ghidra protocol extensions are not currently supported (e.g., ghidra:http://...).
        @param url ghidra URL
        @return true if specified URL refers to a Ghidra server 
         repository (ghidra://host/repositoryNAME/path...)
        """
        ...

    @staticmethod
    def isServerURL(url: java.net.URL) -> bool:
        """
        Determine if the specified URL is any type of server URL.
         No checking is performed as to the existence of the server or repository.
        @param url ghidra URL
        @return true if specified URL refers to a Ghidra server 
         repository (ghidra://host/repositoryNAME/path...)
        """
        ...

    @staticmethod
    def localProjectExists(url: java.net.URL) -> bool:
        """
        Determine if the specified URL refers to a local project and
         it exists.
        @param url ghidra URL
        @return true if specified URL refers to a local project and
         it exists.
        """
        ...

    @overload
    @staticmethod
    def makeURL(projectLocator: ghidra.framework.model.ProjectLocator) -> java.net.URL:
        """
        Create a URL which refers to a local Ghidra project
        @param projectLocator absolute project location
        @return local Ghidra project URL
        @throws IllegalArgumentException if {@code projectLocator} does not have an absolute location
        """
        ...

    @overload
    @staticmethod
    def makeURL(dirPath: unicode, projectName: unicode) -> java.net.URL:
        """
        Create a URL which refers to a local Ghidra project
        @param dirPath absolute path of project location directory
        @param projectName name of project
        @return local Ghidra project URL
        """
        ...

    @overload
    @staticmethod
    def makeURL(host: unicode, port: int, repositoryName: unicode) -> java.net.URL:
        """
        Create a URL which refers to Ghidra Server repository and its root folder
        @param host server host name/address
        @param port optional server port (a value &lt;= 0 refers to the default port)
        @param repositoryName repository name
        @return Ghidra Server repository URL
        """
        ...

    @overload
    @staticmethod
    def makeURL(projectLocator: ghidra.framework.model.ProjectLocator, projectFilePath: unicode, ref: unicode) -> java.net.URL:
        """
        Create a URL which refers to a local Ghidra project with optional project file and ref
        @param projectLocator local project locator
        @param projectFilePath file path (e.g., /a/b/c, may be null)
        @param ref location reference (may be null)
        @return local Ghidra project URL
        @throws IllegalArgumentException if invalid {@code projectFilePath} specified or if URL 
         instantion fails.
        """
        ...

    @overload
    @staticmethod
    def makeURL(host: unicode, port: int, repositoryName: unicode, repositoryPath: unicode) -> java.net.URL:
        """
        Create a URL which refers to Ghidra Server repository content.  Path may correspond 
         to either a file or folder.
        @param host server host name/address
        @param port optional server port (a value &lt;= 0 refers to the default port)
        @param repositoryName repository name
        @param repositoryPath absolute folder or file path within repository.
         Folder paths should end with a '/' character.
        @return Ghidra Server repository content URL
        """
        ...

    @overload
    @staticmethod
    def makeURL(projectLocation: unicode, projectName: unicode, projectFilePath: unicode, ref: unicode) -> java.net.URL:
        """
        Create a URL which refers to a local Ghidra project with optional project file and ref
        @param projectLocation absolute path of project location directory
        @param projectName name of project
        @param projectFilePath file path (e.g., /a/b/c, may be null)
        @param ref location reference (may be null)
        @return local Ghidra project URL
        """
        ...

    @overload
    @staticmethod
    def makeURL(host: unicode, port: int, repositoryName: unicode, repositoryPath: unicode, ref: unicode) -> java.net.URL:
        """
        Create a URL which refers to Ghidra Server repository content.  Path may correspond 
         to either a file or folder.
        @param host server host name/address
        @param port optional server port (a value &lt;= 0 refers to the default port)
        @param repositoryName repository name
        @param repositoryPath absolute folder or file path within repository.
        @param ref ref or null 
         Folder paths should end with a '/' character.
        @return Ghidra Server repository content URL
        """
        ...

    @overload
    @staticmethod
    def makeURL(host: unicode, port: int, repositoryName: unicode, repositoryFolderPath: unicode, fileName: unicode, ref: unicode) -> java.net.URL:
        """
        Create a URL which refers to Ghidra Server repository content.  Path may correspond 
         to either a file or folder.
        @param host server host name/address
        @param port optional server port (a value &lt;= 0 refers to the default port)
        @param repositoryName repository name
        @param repositoryFolderPath absolute folder path within repository.
        @param fileName name of a file or folder contained within the specified {@code repositoryFolderPath}
        @param ref optional URL ref or null
         Folder paths should end with a '/' character.
        @return Ghidra Server repository content URL
        @throws IllegalArgumentException if invalid arguments are specified
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def toURL(projectPathOrURL: unicode) -> java.net.URL:
        """
        Create a Ghidra URL from a string form of Ghidra URL or local project path.
         This method can consume strings produced by the getDisplayString method.
        @param projectPathOrURL {@literal project path (<absolute-directory>/<project-name>)} or 
         string form of Ghidra URL.
        @return local Ghidra project URL
        @see #getDisplayString(URL)
        @throws IllegalArgumentException invalid path or URL specified
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

