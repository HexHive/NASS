import ghidra.framework.data
import ghidra.framework.model
import ghidra.framework.store
import ghidra.util.task
import java.lang
import java.net
import javax.swing


class LinkHandler(ghidra.framework.data.DBContentHandler):
    """
    NOTE:  ALL ContentHandler implementations MUST END IN "ContentHandler".  If not,
     the ClassSearcher will not find them.
 
     LinkHandler defines an application interface for handling domain files which are
     shortcut links to another supported content type.
    """

    LINK_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Gui/lib/Gui.jar!/images/core.png
    URL_METADATA_KEY: unicode = u'link.url'



    def __init__(self): ...



    def createFile(self, __a0: ghidra.framework.store.FileSystem, __a1: ghidra.framework.store.FileSystem, __a2: unicode, __a3: unicode, __a4: ghidra.framework.model.DomainObject, __a5: ghidra.util.task.TaskMonitor) -> long: ...

    def equals(self, __a0: object) -> bool: ...

    def getChangeSet(self, versionedFolderItem: ghidra.framework.store.FolderItem, olderVersion: int, newerVersion: int) -> ghidra.framework.model.ChangeSet: ...

    def getClass(self) -> java.lang.Class: ...

    def getContentType(self) -> unicode: ...

    def getContentTypeDisplayString(self) -> unicode: ...

    def getDefaultToolName(self) -> unicode: ...

    def getDomainObject(self, item: ghidra.framework.store.FolderItem, userfs: ghidra.framework.store.FileSystem, checkoutId: long, okToUpgrade: bool, okToRecover: bool, consumer: object, monitor: ghidra.util.task.TaskMonitor) -> object: ...

    def getDomainObjectClass(self) -> java.lang.Class: ...

    def getIcon(self) -> javax.swing.Icon:
        """
        Get the base icon for this link-file which does not include the 
         link overlay icon.
        """
        ...

    def getImmutableObject(self, item: ghidra.framework.store.FolderItem, consumer: object, version: int, minChangeVersion: int, monitor: ghidra.util.task.TaskMonitor) -> object: ...

    def getLinkHandler(self) -> ghidra.framework.data.LinkHandler: ...

    def getMergeManager(self, resultsObj: ghidra.framework.model.DomainObject, sourceObj: ghidra.framework.model.DomainObject, originalObj: ghidra.framework.model.DomainObject, latestObj: ghidra.framework.model.DomainObject) -> ghidra.framework.data.DomainObjectMergeManager: ...

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
    def icon(self) -> javax.swing.Icon: ...

    @property
    def privateContentType(self) -> bool: ...