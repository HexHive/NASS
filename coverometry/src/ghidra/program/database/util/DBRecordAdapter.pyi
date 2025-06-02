import db
import java.lang


class DBRecordAdapter(object):
    """
    Interface to get a record iterator.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getRecordCount(self) -> int:
        """
        Get the number of records in table
        @return total record count
        """
        ...

    def getRecords(self) -> db.RecordIterator:
        """
        Get a record iterator for all records.
        @return record iterator
        @throws IOException if there was a problem accessing the database
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
    def recordCount(self) -> int: ...

    @property
    def records(self) -> db.RecordIterator: ...