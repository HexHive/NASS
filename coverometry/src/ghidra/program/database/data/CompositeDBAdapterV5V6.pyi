import db
import ghidra.program.database.data
import java.lang


class CompositeDBAdapterV5V6(ghidra.program.database.data.CompositeDBAdapter):
    """
    Version 5 and 6 implementation for accessing the Composite database table. 
     Version 5 introduced the retained computed alignment to reduce the
     need for recalculation and to allow for improved change detection.
     Version 6 did not change the schema but corresponds to the elimination
     of Structure flex-arrays which are supported in read-only mode under
     the older version 5 adapter version.
 
     NOTE: Use of tablePrefix introduced with adapter V6.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getRecordCount(self) -> int: ...

    def getRecords(self) -> db.RecordIterator: ...

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

