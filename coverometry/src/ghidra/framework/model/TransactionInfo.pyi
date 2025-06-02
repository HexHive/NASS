from typing import List
import ghidra.framework.model
import ghidra.framework.model.TransactionInfo
import java.lang
import java.util


class TransactionInfo(object):





    class Status(java.lang.Enum):
        ABORTED: ghidra.framework.model.TransactionInfo.Status = ABORTED
        COMMITTED: ghidra.framework.model.TransactionInfo.Status = COMMITTED
        NOT_DONE: ghidra.framework.model.TransactionInfo.Status = NOT_DONE
        NOT_DONE_BUT_ABORTED: ghidra.framework.model.TransactionInfo.Status = NOT_DONE_BUT_ABORTED







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def describeConstable(self) -> java.util.Optional: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getDeclaringClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def name(self) -> unicode: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def ordinal(self) -> int: ...

        def toString(self) -> unicode: ...

        @overload
        @staticmethod
        def valueOf(__a0: unicode) -> ghidra.framework.model.TransactionInfo.Status: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.framework.model.TransactionInfo.Status]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode:
        """
        Returns the description of this transaction.
        @return the description of this transaction
        """
        ...

    def getID(self) -> long: ...

    def getOpenSubTransactions(self) -> List[unicode]:
        """
        Returns the list of open sub-transactions that are contained
         inside this transaction.
        @return the list of open sub-transactions
        """
        ...

    def getStatus(self) -> ghidra.framework.model.TransactionInfo.Status:
        """
        Get the status of the corresponding transaction.
        @return status
        """
        ...

    def hasCommittedDBTransaction(self) -> bool:
        """
        Determine if the corresponding transaction, and all of its sub-transactions, has been 
         comitted to the underlying database.
        @return true if the corresponding transaction has been comitted, else false.
        """
        ...

    def hashCode(self) -> int: ...

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
    def ID(self) -> long: ...

    @property
    def description(self) -> unicode: ...

    @property
    def openSubTransactions(self) -> java.util.ArrayList: ...

    @property
    def status(self) -> ghidra.framework.model.TransactionInfo.Status: ...