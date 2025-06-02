import ghidra.framework.data
import ghidra.framework.model
import ghidra.framework.store
import ghidra.util.task
import java.lang
import java.net
import javax.swing


class FolderLinkContentHandler(ghidra.framework.data.LinkHandler):
    """
     provide folder-link support.  
     Implementation relies on AppInfo#getActiveProject() to provide life-cycle 
     management for related transient-projects opened while following folder-links.
    """

    FOLDER_LINK_CONTENT_TYPE: unicode = u'FolderLink'
    INSTANCE: ghidra.framework.data.FolderLinkContentHandler



    def __init__(self): ...



    def createFile(self, fs: ghidra.framework.store.FileSystem, userfs: ghidra.framework.store.FileSystem, path: unicode, name: unicode, obj: ghidra.framework.model.DomainObject, monitor: ghidra.util.task.TaskMonitor) -> long: ...

    def equals(self, __a0: object) -> bool: ...

    def getChangeSet(self, versionedFolderItem: ghidra.framework.store.FolderItem, olderVersion: int, newerVersion: int) -> ghidra.framework.model.ChangeSet: ...

    def getClass(self) -> java.lang.Class: ...

    def getContentType(self) -> unicode: ...

    def getContentTypeDisplayString(self) -> unicode: ...

    def getDefaultToolName(self) -> unicode: ...

    def getDomainObject(self, item: ghidra.framework.store.FolderItem, userfs: ghidra.framework.store.FileSystem, checkoutId: long, okToUpgrade: bool, okToRecover: bool, consumer: object, monitor: ghidra.util.task.TaskMonitor) -> object: ...

    def getDomainObjectClass(self) -> java.lang.Class: ...

    def getIcon(self) -> javax.swing.Icon: ...

    def getImmutableObject(self, item: ghidra.framework.store.FolderItem, consumer: object, version: int, minChangeVersion: int, monitor: ghidra.util.task.TaskMonitor) -> object: ...

    def getLinkHandler(self) -> ghidra.framework.data.LinkHandler: ...

    def getMergeManager(self, resultsObj: ghidra.framework.model.DomainObject, sourceObj: ghidra.framework.model.DomainObject, originalObj: ghidra.framework.model.DomainObject, latestObj: ghidra.framework.model.DomainObject) -> ghidra.framework.data.DomainObjectMergeManager: ...

    @staticmethod
    def getReadOnlyLinkedFolder(folderLinkFile: ghidra.framework.model.DomainFile) -> ghidra.framework.data.LinkedGhidraFolder:
        """
        Get linked domain folder
        @param folderLinkFile folder-link file.
        @return {@link LinkedGhidraFolder} referenced by specified folder-link file or null if 
         folderLinkFile content type is not {@value #FOLDER_LINK_CONTENT_TYPE}.
        @throws IOException if an IO or folder item access error occurs
        """
        ...

    def getReadOnlyObject(self, item: ghidra.framework.store.FolderItem, version: int, okToUpgrade: bool, consumer: object, monitor: ghidra.util.task.TaskMonitor) -> object: ...

    @staticmethod
    def getURL(linkFile: ghidra.framework.model.DomainFile) -> java.net.URL:
        """
        Get the link URL which corresponds to the specified link file.
         See {@link DomainFile#isLinkFile()}.
        @param linkFile link-file domain file
        @return link URL
        @throws MalformedURLException if link is bad or unsupported.
        @throws IOException if IO error or supported link file not specified
        """
        ...

    def hashCode(self) -> int: ...

    def isPrivateContentType(self) -> bool: ...

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
    def contentType(self) -> unicode: ...

    @property
    def contentTypeDisplayString(self) -> unicode: ...

    @property
    def defaultToolName(self) -> unicode: ...

    @property
    def domainObjectClass(self) -> java.lang.Class: ...

    @property
    def icon(self) -> javax.swing.Icon: ...