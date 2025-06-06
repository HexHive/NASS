from typing import List
import db
import ghidra.framework.model
import ghidra.framework.options
import ghidra.util.task
import java.io
import java.lang
import java.util
import utility.function


class UndoableDomainObject(ghidra.framework.model.DomainObject, ghidra.framework.model.Undoable, object):
    """
    UndoableDomainObject extends a domain object to provide transaction
     support and the ability to undo and redo changes made within a stack of 
     recent transactions.  Each transactions may contain many sub-transactions which
     reflect concurrent changes to the domain object.  If any sub-transaction fails to commit,
     all concurrent sub-transaction changes will be rolled-back. 
 
     NOTE: A transaction must be started in order
     to make any change to this domain object - failure to do so will result in a 
     IOException.
    """

    DO_DOMAIN_FILE_CHANGED: int = 2
    DO_OBJECT_CLOSED: int = 6
    DO_OBJECT_ERROR: int = 8
    DO_OBJECT_RENAMED: int = 3
    DO_OBJECT_RESTORED: int = 4
    DO_OBJECT_SAVED: int = 1
    DO_PROPERTY_CHANGED: int = 5
    undoLock: object = java.lang.Object@5718d051







    def addCloseListener(self, __a0: ghidra.framework.model.DomainObjectClosedListener) -> None: ...

    def addConsumer(self, __a0: object) -> bool: ...

    def addListener(self, __a0: ghidra.framework.model.DomainObjectListener) -> None: ...

    def addSynchronizedDomainObject(self, domainObj: ghidra.framework.model.DomainObject) -> None:
        """
        Synchronize the specified domain object with this domain object
         using a shared transaction manager.  If either or both is already shared, 
         a transition to a single shared transaction manager will be 
         performed.
        @param domainObj the domain object
        @throws LockException if lock or open transaction is active on either
         this or the specified domain object
        """
        ...

    def addTransactionListener(self, __a0: ghidra.framework.model.TransactionListener) -> None: ...

    def canLock(self) -> bool: ...

    def canRedo(self) -> bool: ...

    def canSave(self) -> bool: ...

    def canUndo(self) -> bool: ...

    def clearUndo(self) -> None: ...

    def createPrivateEventQueue(self, __a0: ghidra.framework.model.DomainObjectListener, __a1: int) -> ghidra.framework.model.EventQueueID: ...

    def endTransaction(self, transactionID: int, commit: bool) -> None:
        """
        Terminate the specified transaction for this domain object.
        @param transactionID transaction ID obtained from startTransaction method
        @param commit if true the changes made in this transaction will be marked for commit,
         if false this and any concurrent transaction will be rolled-back.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def flushEvents(self) -> None: ...

    def flushPrivateEventQueue(self, __a0: ghidra.framework.model.EventQueueID) -> None: ...

    def forceLock(self, __a0: bool, __a1: unicode) -> None: ...

    def getAllRedoNames(self) -> List[object]: ...

    def getAllUndoNames(self) -> List[object]: ...

    def getClass(self) -> java.lang.Class: ...

    def getConsumerList(self) -> java.util.ArrayList: ...

    def getCurrentTransactionInfo(self) -> ghidra.framework.model.TransactionInfo:
        """
        Returns the current transaction info
        @return the current transaction info
        """
        ...

    def getDescription(self) -> unicode: ...

    def getDomainFile(self) -> ghidra.framework.model.DomainFile: ...

    def getMetadata(self) -> java.util.Map: ...

    def getModificationNumber(self) -> long: ...

    def getName(self) -> unicode: ...

    def getOptions(self, __a0: unicode) -> ghidra.framework.options.Options: ...

    def getOptionsNames(self) -> List[object]: ...

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

    def hasExclusiveAccess(self) -> bool: ...

    def hasTerminatedTransaction(self) -> bool:
        """
        Returns true if the last transaction was terminated from the action that started it.
        @return true if the last transaction was terminated from the action that started it.
        """
        ...

    def hashCode(self) -> int: ...

    def isChangeable(self) -> bool: ...

    def isChanged(self) -> bool: ...

    def isClosed(self) -> bool: ...

    def isLocked(self) -> bool: ...

    def isSendingEvents(self) -> bool: ...

    def isTemporary(self) -> bool: ...

    def isUsedBy(self, __a0: object) -> bool: ...

    def lock(self, __a0: unicode) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def openTransaction(self, description: unicode) -> db.Transaction:
        """
        Open new transaction.  This should generally be done with a try-with-resources block:
         <pre>
         try (Transaction tx = dobj.openTransaction(description)) {
         	// ... Do something
         }
         </pre>
        @param description a short description of the changes to be made.
        @return transaction object
        @throws IllegalStateException if this {@link DomainObject} has already been closed.
        """
        ...

    def redo(self) -> None: ...

    def release(self, __a0: object) -> None: ...

    def releaseSynchronizedDomainObject(self) -> None:
        """
        Remove this domain object from a shared transaction manager.  If
         this object has not been synchronized with others via a shared
         transaction manager, this method will have no affect.
        @throws LockException if lock or open transaction is active
        """
        ...

    def removeCloseListener(self, __a0: ghidra.framework.model.DomainObjectClosedListener) -> None: ...

    def removeListener(self, __a0: ghidra.framework.model.DomainObjectListener) -> None: ...

    def removePrivateEventQueue(self, __a0: ghidra.framework.model.EventQueueID) -> bool: ...

    def removeTransactionListener(self, __a0: ghidra.framework.model.TransactionListener) -> None: ...

    def save(self, __a0: unicode, __a1: ghidra.util.task.TaskMonitor) -> None: ...

    def saveToPackedFile(self, __a0: java.io.File, __a1: ghidra.util.task.TaskMonitor) -> None: ...

    def setEventsEnabled(self, __a0: bool) -> None: ...

    def setName(self, __a0: unicode) -> None: ...

    def setTemporary(self, __a0: bool) -> None: ...

    @overload
    def startTransaction(self, description: unicode) -> int:
        """
        Start a new transaction in order to make changes to this domain object.
         All changes must be made in the context of a transaction. 
         If a transaction is already in progress, a sub-transaction 
         of the current transaction will be returned.
        @param description brief description of transaction
        @return transaction ID
        @throws DomainObjectLockedException the domain object is currently locked
        @throws TerminatedTransactionException an existing transaction which has not yet ended was terminated early.
         Sub-transactions are not permitted until the terminated transaction ends.
        """
        ...

    @overload
    def startTransaction(self, description: unicode, listener: ghidra.framework.model.AbortedTransactionListener) -> int:
        """
        Start a new transaction in order to make changes to this domain object.
         All changes must be made in the context of a transaction. 
         If a transaction is already in progress, a sub-transaction 
         of the current transaction will be returned.
        @param description brief description of transaction
        @param listener listener to be notified if the transaction is aborted.
        @return transaction ID
        @throws DomainObjectLockedException the domain object is currently locked
        @throws TerminatedTransactionException an existing transaction which has not yet ended was terminated early.
         Sub-transactions are not permitted until the terminated transaction ends.
        """
        ...

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
    def withTransaction(self, description: unicode, callback: utility.function.ExceptionalCallback) -> None:
        """
        Performs the given callback inside of a transaction.  Use this method in place of the more
         verbose try/catch/finally semantics.
         <p>
         <pre>
         program.withTransaction("My Description", () -> {
         	// ... Do something
         });
         </pre>
 
         <p>
         Note: the transaction created by this method will always be committed when the call is 
         finished.  If you need the ability to abort transactions, then you need to use the other 
         methods on this interface.
        @param description brief description of transaction
        @param callback the callback that will be called inside of a transaction
        @throws E any exception that may be thrown in the given callback
        """
        ...

    @overload
    def withTransaction(self, description: unicode, supplier: utility.function.ExceptionalSupplier) -> object:
        """
        Calls the given supplier inside of a transaction.  Use this method in place of the more
         verbose try/catch/finally semantics.
         <p>
         <pre>
         program.withTransaction("My Description", () -> {
         	// ... Do something
         	return result;
         });
         </pre>
         <p>
         If you do not need to supply a result, then use 
         {@link #withTransaction(String, ExceptionalCallback)} instead.
        @param <E> the exception that may be thrown from this method
        @param <T> the type of result returned by the supplier
        @param description brief description of transaction
        @param supplier the supplier that will be called inside of a transaction
        @return the result returned by the supplier
        @throws E any exception that may be thrown in the given callback
        """
        ...

    @property
    def allRedoNames(self) -> List[object]: ...

    @property
    def allUndoNames(self) -> List[object]: ...

    @property
    def changeable(self) -> bool: ...

    @property
    def changed(self) -> bool: ...

    @property
    def closed(self) -> bool: ...

    @property
    def consumerList(self) -> java.util.ArrayList: ...

    @property
    def currentTransactionInfo(self) -> ghidra.framework.model.TransactionInfo: ...

    @property
    def description(self) -> unicode: ...

    @property
    def domainFile(self) -> ghidra.framework.model.DomainFile: ...

    @property
    def eventsEnabled(self) -> None: ...  # No getter available.

    @eventsEnabled.setter
    def eventsEnabled(self, value: bool) -> None: ...

    @property
    def locked(self) -> bool: ...

    @property
    def metadata(self) -> java.util.Map: ...

    @property
    def modificationNumber(self) -> long: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def optionsNames(self) -> List[object]: ...

    @property
    def redoName(self) -> unicode: ...

    @property
    def sendingEvents(self) -> bool: ...

    @property
    def synchronizedDomainObjects(self) -> List[ghidra.framework.model.DomainObject]: ...

    @property
    def temporary(self) -> bool: ...

    @temporary.setter
    def temporary(self, value: bool) -> None: ...

    @property
    def undoName(self) -> unicode: ...