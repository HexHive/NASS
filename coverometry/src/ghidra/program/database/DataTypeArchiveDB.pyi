from typing import List
import db
import ghidra.framework.data
import ghidra.framework.model
import ghidra.framework.options
import ghidra.program.database
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util
import ghidra.util.task
import java.io
import java.lang
import java.util
import utility.function


class DataTypeArchiveDB(ghidra.framework.data.DomainObjectAdapterDB, ghidra.program.model.listing.DataTypeArchive, ghidra.program.util.DataTypeArchiveChangeManager):
    """
    Database implementation for Data Type Archive.
    """

    ARCHIVE_INFO: unicode = u'Data Type Archive Information'
    ARCHIVE_SETTINGS: unicode = u'Data Type Archive Settings'
    CREATED_WITH_GHIDRA_VERSION: unicode = u'Created With Ghidra Version'
    DATE_CREATED: unicode = u'Date Created'
    JANUARY_1_1970: java.util.Date = Thu Jan 01 00:00:00 UTC 1970



    @overload
    def __init__(self, folder: ghidra.framework.model.DomainFolder, name: unicode, consumer: object):
        """
        Constructs a new DataTypeArchiveDB within a project folder.
        @param folder folder within which the project archive will be created
        @param name the name of the data type archive
        @param consumer the object that is using this data type archive.
        @throws IOException if there is an error accessing the database.
        @throws InvalidNameException
        @throws DuplicateNameException
        """
        ...

    @overload
    def __init__(self, dbh: db.DBHandle, openMode: int, monitor: ghidra.util.task.TaskMonitor, consumer: object):
        """
        Constructs a new DataTypeArchiveDB
        @param dbh a handle to an open data type archive database.
        @param openMode one of:
         		READ_ONLY: the original database will not be modified
         		UPDATE: the database can be written to.
         		UPGRADE: the database is upgraded to the latest schema as it is opened.
        @param monitor TaskMonitor that allows the open to be canceled.
        @param consumer the object that keeping the program open.
        @throws IOException if an error accessing the database occurs.
        @throws VersionException if database version does not match implementation, UPGRADE may be possible.
        @throws CancelledException if instantiation is canceled by monitor
        """
        ...



    def addCloseListener(self, listener: ghidra.framework.model.DomainObjectClosedListener) -> None: ...

    def addConsumer(self, consumer: object) -> bool: ...

    def addListener(self, l: ghidra.framework.model.DomainObjectListener) -> None: ...

    def addSynchronizedDomainObject(self, domainObj: ghidra.framework.model.DomainObject) -> None:
        """
        Synchronize the specified domain object with this domain object
         using a shared transaction manager.  If either or both is already shared,
         a transition to a single shared transaction manager will be
         performed.
        @param domainObj
        @throws LockException if lock or open transaction is active on either
         this or the specified domain object
        """
        ...

    def addTransactionListener(self, listener: ghidra.framework.model.TransactionListener) -> None:
        """
        Adds the given transaction listener to this domain object
        @param listener the new transaction listener to add
        """
        ...

    def canLock(self) -> bool: ...

    def canRedo(self) -> bool: ...

    def canSave(self) -> bool: ...

    def canUndo(self) -> bool: ...

    def categoryAdded(self, categoryID: long, type: int, oldValue: object, newValue: object) -> None:
        """
        Notification that a category was added.
        @param categoryID the id of the data type that was added.
        @param type the type of changed (should always be CATEGORY_ADDED)
        @param oldValue always null
        @param newValue new value depends on the type.
        """
        ...

    def categoryChanged(self, categoryID: long, type: int, oldValue: object, newValue: object) -> None:
        """
        Notification that a category was changed.
        @param categoryID the id of the data type that was added.
        @param type the type of changed
        @param oldValue old value depends on the type.
        @param newValue new value depends on the type.
        """
        ...

    def checkExclusiveAccess(self) -> None: ...

    def clearUndo(self) -> None: ...

    def createPrivateEventQueue(self, listener: ghidra.framework.model.DomainObjectListener, maxDelay: int) -> ghidra.framework.model.EventQueueID: ...

    def dataTypeAdded(self, dataTypeID: long, type: int, oldValue: object, newValue: object) -> None:
        """
        Notification that a data type was added.
        @param dataTypeID the id if the data type that was added.
        @param type should always be DATATYPE_ADDED
        @param oldValue always null
        @param newValue the data type added.
        """
        ...

    def dataTypeChanged(self, dataTypeID: long, type: int, isAutoResponseChange: bool, oldValue: object, newValue: object) -> None:
        """
        notification the a data type has changed
        @param dataTypeID the id of the data type that changed.
        @param type the type of the change (moved, renamed, etc.)
        @param isAutoResponseChange true if change is an auto-response change caused by 
         another datatype's change (e.g., size, alignment), else false in which case this
         change will be added to archive change-set to aid merge conflict detection.
        @param oldValue the old data type.
        @param newValue the new data type.
        """
        ...

    def dbError(self, e: java.io.IOException) -> None: ...

    def endTransaction(self, transactionID: int, commit: bool) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def fireEvent(self, ev: ghidra.framework.model.DomainObjectChangeRecord) -> None:
        """
        Fires the specified event.
        @param ev event to fire
        """
        ...

    def flushEvents(self) -> None: ...

    def flushPrivateEventQueue(self, id: ghidra.framework.model.EventQueueID) -> None: ...

    def flushWriteCache(self) -> None:
        """
        Flush any pending database changes.
         This method will be invoked by the transaction manager
         prior to closing a transaction.
        """
        ...

    def forceLock(self, rollback: bool, reason: unicode) -> None: ...

    def getAllRedoNames(self) -> List[unicode]: ...

    def getAllUndoNames(self) -> List[unicode]: ...

    def getChangeSet(self) -> ghidra.framework.data.DomainObjectDBChangeSet:
        """
        Returns the change set corresponding to all unsaved changes in this domain object.
        @return the change set corresponding to all unsaved changes in this domain object
        """
        ...

    def getChangeStatus(self) -> bool:
        """
        Return "changed" status
        @return true if this object has changed
        """
        ...

    def getChanges(self) -> ghidra.program.database.DataTypeArchiveDBChangeSet:
        """
        @see ghidra.program.model.listing.Program#getChanges()
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getConsumerList(self) -> List[object]: ...

    @staticmethod
    def getContentHandler(dobj: ghidra.framework.model.DomainObject) -> ghidra.framework.data.ContentHandler:
        """
        Get the ContentHandler associated with the specified domain object
        @param dobj domain object
        @return content handler
        @throws IOException if no content handler can be found
        """
        ...

    def getCreationDate(self) -> java.util.Date:
        """
        @see ghidra.program.model.listing.Program#getCreationDate()
        """
        ...

    def getCurrentTransactionInfo(self) -> ghidra.framework.model.TransactionInfo: ...

    def getDBHandle(self) -> db.DBHandle:
        """
        Returns the open handle to the underlying database.
        """
        ...

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        @see ghidra.program.model.listing.Program#getDataTypeManager()
        """
        ...

    def getDefaultPointerSize(self) -> int:
        """
        @see ghidra.program.model.listing.Program#getDefaultPointerSize()
        """
        ...

    def getDescription(self) -> unicode: ...

    def getDomainFile(self) -> ghidra.framework.model.DomainFile: ...

    def getLock(self) -> ghidra.util.Lock: ...

    def getMetadata(self) -> java.util.Map: ...

    def getModificationNumber(self) -> long: ...

    def getName(self) -> unicode: ...

    def getOptions(self, propertyListName: unicode) -> ghidra.framework.options.Options: ...

    def getOptionsNames(self) -> List[unicode]:
        """
        Returns all properties lists contained by this domain object.
        @return all property lists contained by this domain object.
        """
        ...

    def getRedoName(self) -> unicode: ...

    def getSynchronizedDomainObjects(self) -> List[ghidra.framework.model.DomainObject]:
        """
        Return array of all domain objects synchronized with a
         shared transaction manager.
        @return returns array of synchronized domain objects or
         null if this domain object is not synchronized with others.
        """
        ...

    def getUndoName(self) -> unicode: ...

    def getUndoStackDepth(self) -> int:
        """
        Returns the undo stack depth.
         (The number of items on the undo stack)
         This method is for JUnits.
        @return the undo stack depth
        """
        ...

    def hasExclusiveAccess(self) -> bool: ...

    def hasTerminatedTransaction(self) -> bool: ...

    def hashCode(self) -> int: ...

    def invalidate(self) -> None:
        """
        @see ghidra.program.model.listing.Program#invalidate()
        """
        ...

    def invalidateWriteCache(self) -> None:
        """
        Invalidate (i.e., clear) any pending database changes not yet written.
         This method will be invoked by the transaction manager
         prior to aborting a transaction.
        """
        ...

    def isChangeable(self) -> bool: ...

    def isChanged(self) -> bool: ...

    def isClosed(self) -> bool: ...

    def isLocked(self) -> bool: ...

    def isSendingEvents(self) -> bool: ...

    def isTemporary(self) -> bool: ...

    def isUsedBy(self, consumer: object) -> bool:
        """
        Returns true if the given tool is using this object.
        """
        ...

    def lock(self, reason: unicode) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openTransaction(self, description: unicode) -> db.Transaction: ...

    def redo(self) -> None: ...

    def release(self, consumer: object) -> None: ...

    def releaseSynchronizedDomainObject(self) -> None:
        """
        Release this domain object from a shared transaction manager.  If
         this object has not been synchronized with others via a shared
         transaction manager, this method will have no affect.
        @throws LockException if lock or open transaction is active
        """
        ...

    def removeCloseListener(self, listener: ghidra.framework.model.DomainObjectClosedListener) -> None: ...

    def removeListener(self, l: ghidra.framework.model.DomainObjectListener) -> None: ...

    def removePrivateEventQueue(self, id: ghidra.framework.model.EventQueueID) -> bool: ...

    def removeTransactionListener(self, listener: ghidra.framework.model.TransactionListener) -> None:
        """
        Removes the given transaction listener from this domain object.
        @param listener the transaction listener to remove
        """
        ...

    def save(self, comment: unicode, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def saveToPackedFile(self, outputFile: java.io.File, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def setChanged(self, type: int, oldValue: object, newValue: object) -> None:
        """
        Mark the state this Data Type Archive as having changed and generate
         the event.  Any or all parameters may be null.
        @param type event type
        @param oldValue original value
        @param newValue new value
        """
        ...

    @staticmethod
    def setDefaultContentClass(doClass: java.lang.Class) -> None:
        """
        Set default content type
        @param doClass default domain object implementation
        """
        ...

    def setEventsEnabled(self, v: bool) -> None: ...

    def setName(self, newName: unicode) -> None: ...

    def setObjChanged(self, type: int, affectedObj: object, oldValue: object, newValue: object) -> None:
        """
        Mark the state of a Program as having changed and generate
         the event.  Any or all parameters may be null.
         NOTE: ChangeSet data will not be updated since this a very generic
         change not related to a specific address.
        @param type event type
        @param affectedObj object that is the subject of the event
        @param oldValue original value or an Object that is related to
         the event
        @param newValue new value or an Object that is related to the
         the event
        """
        ...

    def setTemporary(self, state: bool) -> None: ...

    @overload
    def startTransaction(self, description: unicode) -> int: ...

    @overload
    def startTransaction(self, description: unicode, listener: ghidra.framework.model.AbortedTransactionListener) -> int: ...

    def toString(self) -> unicode: ...

    def undo(self) -> None: ...

    def unlock(self) -> None: ...

    def updateID(self) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @overload
    def withTransaction(self, __a0: unicode, __a1: utility.function.ExceptionalCallback) -> None: ...

    @overload
    def withTransaction(self, __a0: unicode, __a1: utility.function.ExceptionalSupplier) -> object: ...

    @property
    def changeable(self) -> bool: ...

    @property
    def changes(self) -> ghidra.program.database.DataTypeArchiveDBChangeSet: ...

    @property
    def creationDate(self) -> java.util.Date: ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager: ...

    @property
    def defaultPointerSize(self) -> int: ...

    @property
    def description(self) -> unicode: ...

    @property
    def metadata(self) -> java.util.Map: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...