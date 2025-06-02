import db
import ghidra.framework.data
import ghidra.framework.model
import ghidra.framework.store
import ghidra.program.database
import ghidra.util.task
import java.lang
import javax.swing


class ProgramContentHandler(ghidra.framework.data.DBWithUserDataContentHandler):
    """
    ProgramContentHandler converts between Program instantiations
     and FolderItem storage.  This class also produces the appropriate Icon for 
     Program files.
    """

    PROGRAM_CONTENT_TYPE: unicode = u'Program'
    PROGRAM_ICON: javax.swing.Icon



    def __init__(self): ...



    def createFile(self, fs: ghidra.framework.store.FileSystem, userfs: ghidra.framework.store.FileSystem, path: unicode, name: unicode, obj: ghidra.framework.model.DomainObject, monitor: ghidra.util.task.TaskMonitor) -> long: ...

    def equals(self, __a0: object) -> bool: ...

    def getChangeSet(self, item: ghidra.framework.store.FolderItem, fromVer: int, toVer: int) -> ghidra.framework.model.ChangeSet: ...

    def getClass(self) -> java.lang.Class: ...

    def getContentType(self) -> unicode: ...

    def getContentTypeDisplayString(self) -> unicode: ...

    def getDefaultToolName(self) -> unicode: ...

    def getDomainObject(self, item: ghidra.framework.store.FolderItem, userfs: ghidra.framework.store.FileSystem, checkoutId: long, okToUpgrade: bool, recover: bool, consumer: object, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.database.ProgramDB: ...

    def getDomainObjectClass(self) -> java.lang.Class: ...

    def getIcon(self) -> javax.swing.Icon: ...

    def getImmutableObject(self, item: ghidra.framework.store.FolderItem, consumer: object, version: int, minChangeVersion: int, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.database.ProgramDB: ...

    def getLinkHandler(self) -> ghidra.program.database.ProgramLinkContentHandler: ...

    def getMergeManager(self, resultsObj: ghidra.framework.model.DomainObject, sourceObj: ghidra.framework.model.DomainObject, originalObj: ghidra.framework.model.DomainObject, latestObj: ghidra.framework.model.DomainObject) -> ghidra.framework.data.DomainObjectMergeManager: ...

    def getReadOnlyObject(self, item: ghidra.framework.store.FolderItem, version: int, okToUpgrade: bool, consumer: object, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.database.ProgramDB: ...

    def hashCode(self) -> int: ...

    def isPrivateContentType(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeUserDataFile(self, associatedItem: ghidra.framework.store.FolderItem, userFilesystem: ghidra.framework.store.FileSystem) -> None:
        """
        Remove user data file associated with an existing folder item.
        @param associatedItem associated folder item
        @param userFilesystem user data file system from which corresponding data should be removed.
        @throws IOException if an access error occurs
        """
        ...

    def saveUserDataFile(self, associatedDomainObj: ghidra.framework.model.DomainObject, userDbh: db.DBHandle, userfs: ghidra.framework.store.FileSystem, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Create user data file associated with existing content.
         This facilitates the lazy creation of the user data file.
        @param associatedDomainObj associated domain object corresponding to this content handler
        @param userDbh user data handle
        @param userfs private user data filesystem
        @param monitor task monitor
        @throws IOException if an IO or access error occurs
        @throws CancelledException if operation is cancelled by user
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
    def contentType(self) -> unicode: ...

    @property
    def contentTypeDisplayString(self) -> unicode: ...

    @property
    def defaultToolName(self) -> unicode: ...

    @property
    def domainObjectClass(self) -> java.lang.Class: ...

    @property
    def icon(self) -> javax.swing.Icon: ...

    @property
    def linkHandler(self) -> ghidra.program.database.ProgramLinkContentHandler: ...

    @property
    def privateContentType(self) -> bool: ...