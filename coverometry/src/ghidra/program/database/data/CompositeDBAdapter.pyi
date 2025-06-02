import db
import ghidra.program.database.util
import java.lang


class CompositeDBAdapter(object, ghidra.program.database.util.DBRecordAdapter):
    """
    Adapter to access the Composite database table.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getRecordCount(self) -> int:
        """
        Get the number of composite records
        @return total number of composite records
        """
        ...

    def getRecords(self) -> db.RecordIterator:
        """
        Gets an iterator over all composite (structure and union) data type records.
        @return the composite data type record iterator.
        @throws IOException if the database can't be accessed.
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

