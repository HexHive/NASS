from typing import List
import db
import ghidra.framework.data
import ghidra.framework.model
import ghidra.framework.options
import ghidra.program.model.listing
import ghidra.program.model.util
import ghidra.util
import ghidra.util.task
import java.io
import java.lang
import java.util
import utility.function


class ProgramUserDataDB(ghidra.framework.data.DomainObjectAdapterDB, ghidra.program.model.listing.ProgramUserData):
    """
    ProgramUserDataDB stores user data associated with a specific program.
     A ContentHandler should not be created for this class since it must never be stored
     within a DomainFolder.
    """









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

    def checkExclusiveAccess(self) -> None: ...

    def clearUndo(self) -> None: ...

    def createPrivateEventQueue(self, listener: ghidra.framework.model.DomainObjectListener, maxDelay: int) -> ghidra.framework.model.EventQueueID: ...

    def dbError(self, e: java.io.IOException) -> None: ...

    @overload
    def endTransaction(self, transactionID: int) -> None: ...

    @overload
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

    def getBooleanProperty(self, owner: unicode, propertyName: unicode, create: bool) -> ghidra.program.model.util.VoidPropertyMap: ...

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

    def getCurrentTransactionInfo(self) -> ghidra.framework.model.TransactionInfo: ...

    def getDBHandle(self) -> db.DBHandle:
        """
        Returns the open handle to the underlying database.
        """
        ...

    def getDescription(self) -> unicode: ...

    def getDomainFile(self) -> ghidra.framework.model.DomainFile: ...

    def getIntProperty(self, owner: unicode, propertyName: unicode, create: bool) -> ghidra.program.model.util.IntPropertyMap: ...

    def getLock(self) -> ghidra.util.Lock: ...

    def getLongProperty(self, owner: unicode, propertyName: unicode, create: bool) -> ghidra.program.model.util.LongPropertyMap: ...

    def getMetadata(self) -> java.util.Map: ...

    def getModificationNumber(self) -> long: ...

    def getName(self) -> unicode: ...

    def getObjectProperty(self, owner: unicode, propertyName: unicode, saveableObjectClass: java.lang.Class, create: bool) -> ghidra.program.model.util.ObjectPropertyMap: ...

    def getOptions(self, propertyListName: unicode) -> ghidra.framework.options.Options: ...

    def getOptionsNames(self) -> List[unicode]:
        """
        Returns all properties lists contained by this domain object.
        @return all property lists contained by this domain object.
        """
        ...

    def getProperties(self, owner: unicode) -> List[ghidra.program.model.util.PropertyMap]: ...

    def getPropertyOwners(self) -> List[unicode]: ...

    def getRedoName(self) -> unicode: ...

    @overload
    def getStringProperty(self, propertyName: unicode, defaultValue: unicode) -> unicode: ...

    @overload
    def getStringProperty(self, owner: unicode, propertyName: unicode, create: bool) -> ghidra.program.model.util.StringPropertyMap: ...

    def getStringPropertyNames(self) -> java.util.Set: ...

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

    @overload
    def openTransaction(self) -> db.Transaction: ...

    @overload
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

    def removeStringProperty(self, propertyName: unicode) -> unicode: ...

    def removeTransactionListener(self, listener: ghidra.framework.model.TransactionListener) -> None:
        """
        Removes the given transaction listener from this domain object.
        @param listener the transaction listener to remove
        """
        ...

    def save(self, comment: unicode, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    def saveToPackedFile(self, outputFile: java.io.File, monitor: ghidra.util.task.TaskMonitor) -> None: ...

    @staticmethod
    def setDefaultContentClass(doClass: java.lang.Class) -> None:
        """
        Set default content type
        @param doClass default domain object implementation
        """
        ...

    def setEventsEnabled(self, v: bool) -> None: ...

    def setName(self, newName: unicode) -> None: ...

    def setStringProperty(self, propertyName: unicode, value: unicode) -> None: ...

    def setTemporary(self, state: bool) -> None: ...

    @overload
    def startTransaction(self) -> int: ...

    @overload
    def startTransaction(self, description: unicode) -> int: ...

    @overload
    def startTransaction(self, description: unicode, listener: ghidra.framework.model.AbortedTransactionListener) -> int: ...

    def toString(self) -> unicode: ...

    def undo(self) -> None: ...

    def unlock(self) -> None: ...

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

