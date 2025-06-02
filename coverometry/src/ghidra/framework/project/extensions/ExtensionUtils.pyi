import ghidra.framework.project.extensions
import java.io
import java.lang
import java.util


class ExtensionUtils(object):
    """
    Utility class for managing Ghidra Extensions.
 
     Extensions are defined as any archive or folder that contains an extension.properties
     file. This properties file can contain the following attributes:
 
     name (required)
     description
     author
     createdOn (format: MM/dd/yyyy)
     version
 
 
 
     Extensions may be installed/uninstalled by users at runtime, using the
     ExtensionTableProvider. Installation consists of unzipping the extension archive to an
     installation folder, currently {ghidra user settings dir}/Extensions. To uninstall,
     the unpacked folder is simply removed.
    """

    PROPERTIES_FILE_NAME: unicode
    PROPERTIES_FILE_NAME_UNINSTALLED: unicode



    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getActiveInstalledExtensions() -> java.util.Set:
        """
        Gets all known extensions that have not been marked for removal.
        @return set of installed extensions
        """
        ...

    @staticmethod
    def getArchiveExtensions() -> java.util.Set:
        """
        Returns all archive extensions. These are all the extensions found in
         {@link ApplicationLayout#getExtensionArchiveDir}.   This are added to an installation as
         part of the build processes.
         <p>
         Archived extensions may be zip files and directories.
        @return set of archive extensions
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getInstalledExtensions() -> java.util.Set:
        """
        Returns all installed extensions. These are all the extensions found in
         {@link ApplicationLayout#getExtensionInstallationDirs}.
        @return set of installed extensions
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def initializeExtensions() -> None:
        """
        Performs extension maintenance.  This should be called at startup, before any plugins or
         extension points are loaded.
        """
        ...

    @staticmethod
    def install(file: java.io.File) -> bool:
        """
        Installs the given extension file. This can be either an archive (zip) or a directory that
         contains an extension.properties file.
        @param file the extension to install
        @return true if the extension was successfully installed
        """
        ...

    @staticmethod
    def installExtensionFromArchive(extension: ghidra.framework.project.extensions.ExtensionDetails) -> bool:
        """
        Installs the given extension from its declared archive path
        @param extension the extension
        @return true if successful
        """
        ...

    @staticmethod
    def isExtension(file: java.io.File) -> bool:
        """
        Returns true if the given file or directory is a valid ghidra extension.
         <p>
         Note: This means that the zip or directory contains an extension.properties file.
        @param file the zip or directory to inspect
        @return true if the given file represents a valid extension
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

