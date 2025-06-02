import db
import ghidra.framework.data
import ghidra.framework.model
import ghidra.framework.store
import ghidra.util.task
import java.lang
import javax.swing


class DBWithUserDataContentHandler(ghidra.framework.data.DBContentHandler):
    """
    DBContentHandler provides an abstract ContentHandler for 
     domain object content which is stored within a database file.
     This class provides helper methods for working with database files.
    """





    def __init__(self): ...



    def createFile(self, __a0: ghidra.framework.store.FileSystem, __a1: ghidra.framework.store.FileSystem, __a2: unicode, __a3: unicode, __a4: ghidra.framework.model.DomainObject, __a5: ghidra.util.task.TaskMonitor) -> long: ...

    def equals(self, __a0: object) -> bool: ...

    def getChangeSet(self, __a0: ghidra.framework.store.FolderItem, __a1: int, __a2: int) -> ghidra.framework.model.ChangeSet: ...

    def getClass(self) -> java.lang.Class: ...

    def getContentType(self) -> unicode: ...

    def getContentTypeDisplayString(self) -> unicode: ...

    def getDefaultToolName(self) -> unicode: ...

    def getDomainObject(self, __a0: ghidra.framework.store.FolderItem, __a1: ghidra.framework.store.FileSystem, __a2: long, __a3: bool, __a4: bool, __a5: object, __a6: ghidra.util.task.TaskMonitor) -> ghidra.framework.data.DomainObjectAdapter: ...

    def getDomainObjectClass(self) -> java.lang.Class: ...

    def getIcon(self) -> javax.swing.Icon: ...

    def getImmutableObject(self, __a0: ghidra.framework.store.FolderItem, __a1: object, __a2: int, __a3: int, __a4: ghidra.util.task.TaskMonitor) -> ghidra.framework.data.DomainObjectAdapter: ...

    def getLinkHandler(self) -> ghidra.framework.data.LinkHandler: ...

    def getMergeManager(self, __a0: ghidra.framework.model.DomainObject, __a1: ghidra.framework.model.DomainObject, __a2: ghidra.framework.model.DomainObject, __a3: ghidra.framework.model.DomainObject) -> ghidra.framework.data.DomainObjectMergeManager: ...

    def getReadOnlyObject(self, __a0: ghidra.framework.store.FolderItem, __a1: int, __a2: bool, __a3: object, __a4: ghidra.util.task.TaskMonitor) -> ghidra.framework.data.DomainObjectAdapter: ...

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

