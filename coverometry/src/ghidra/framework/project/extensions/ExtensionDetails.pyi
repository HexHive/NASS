import ghidra.framework.project.extensions
import java.io
import java.lang


class ExtensionDetails(object, java.lang.Comparable):
    """
    Representation of a Ghidra extension. This class encapsulates all information required to
     uniquely identify an extension and where (or if) it has been installed.
 
     Note that hashCode and equals have been implemented for this. Two extension
     descriptions are considered equal if they have the same #name attribute; all other
     fields are unimportant except for display purposes.
    """





    def __init__(self, name: unicode, description: unicode, author: unicode, createdOn: unicode, version: unicode):
        """
        Constructor.
        @param name unique name of the extension; cannot be null
        @param description brief explanation of what the extension does; can be null
        @param author creator of the extension; can be null
        @param createdOn creation date of the extension, can be null
        @param version the extension version
        """
        ...



    def clearMarkForUninstall(self) -> bool:
        """
        A companion method for {@link #markForUninstall()} that allows extensions marked for cleanup 
         to be restored to the installed state.
         <p>
         Specifically, the following will be renamed:
         <UL>
         <LI>Module.manifest.uninstalled to Module.manifest</LI>
         <LI>extension.properties.uninstalled to extension.properties</LI>
         </UL>
        @return true if successful
        """
        ...

    @overload
    def compareTo(self, other: ghidra.framework.project.extensions.ExtensionDetails) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, obj: object) -> bool: ...

    def getArchivePath(self) -> unicode:
        """
        Returns the location where the extension archive is located.  The extension archive concept
         is not used for all extensions, but is used for delivering extensions as part of a 
         distribution.
        @return the archive path, or null
        @see ApplicationLayout#getExtensionArchiveDir()
        """
        ...

    def getAuthor(self) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    def getCreatedOn(self) -> unicode: ...

    def getDescription(self) -> unicode: ...

    def getInstallDir(self) -> java.io.File: ...

    def getInstallPath(self) -> unicode:
        """
        Returns the location where this extension is installed. If the extension is not installed 
         this will be null.
        @return the extension path, or null
        """
        ...

    def getName(self) -> unicode: ...

    def getVersion(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isFromArchive(self) -> bool: ...

    def isInstalled(self) -> bool:
        """
        An extension is known to be installed if it has a valid installation path AND that path
         contains a Module.manifest file.   Extensions that are {@link #isPendingUninstall()} are 
         still on the filesystem, may be in use by the tool, but will be removed upon restart.
         <p>
         Note: The module manifest file is a marker that indicates several things; one of which is
         the installation status of an extension. When a user marks an extension to be uninstalled (by
         checking the appropriate checkbox in the {@link ExtensionTableModel}), the only thing
         that is done is to remove this manifest file, which tells the {@link ExtensionTableProvider}
         to remove the entire extension directory on the next launch.
        @return true if the extension is installed.
        """
        ...

    def isInstalledInInstallationFolder(self) -> bool:
        """
        Returns true if this extension is installed under an installation folder or inside of a 
         source control repository folder.
        @return true if this extension is installed under an installation folder or inside of a 
         source control repository folder.
        """
        ...

    def isPendingUninstall(self) -> bool:
        """
        Returns true if this extension is marked to be uninstalled.  The contents of the extension
         still exist and the tool may still be using the extension, but on restart, the extension will
         be removed.
        @return true if marked for uninstall
        """
        ...

    def markForUninstall(self) -> bool:
        """
        Converts the module manifest and extension properties file that are in an installed state to 
         an uninstalled state.
 
         Specifically, the following will be renamed:
         <UL>
         <LI>Module.manifest to Module.manifest.uninstalled</LI>
         <LI>extension.properties = extension.properties.uninstalled</LI>
         </UL>
        @return false if any renames fail
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setArchivePath(self, path: unicode) -> None: ...

    def setAuthor(self, author: unicode) -> None: ...

    def setCreatedOn(self, date: unicode) -> None: ...

    def setDescription(self, description: unicode) -> None: ...

    def setInstallDir(self, installDir: java.io.File) -> None: ...

    def setName(self, name: unicode) -> None: ...

    def setVersion(self, version: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def archivePath(self) -> unicode: ...

    @archivePath.setter
    def archivePath(self, value: unicode) -> None: ...

    @property
    def author(self) -> unicode: ...

    @author.setter
    def author(self, value: unicode) -> None: ...

    @property
    def createdOn(self) -> unicode: ...

    @createdOn.setter
    def createdOn(self, value: unicode) -> None: ...

    @property
    def description(self) -> unicode: ...

    @description.setter
    def description(self, value: unicode) -> None: ...

    @property
    def fromArchive(self) -> bool: ...

    @property
    def installDir(self) -> java.io.File: ...

    @installDir.setter
    def installDir(self, value: java.io.File) -> None: ...

    @property
    def installPath(self) -> unicode: ...

    @property
    def installed(self) -> bool: ...

    @property
    def installedInInstallationFolder(self) -> bool: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def pendingUninstall(self) -> bool: ...

    @property
    def version(self) -> unicode: ...

    @version.setter
    def version(self, value: unicode) -> None: ...