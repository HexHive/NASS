import db
import ghidra.program.database.data
import java.lang


class EnumValueDBAdapterNoTable(ghidra.program.database.data.EnumValueDBAdapter):
    """
    Adapter needed for a read-only version of data type manager that is not going
     to be upgraded, and there is no Enumeration Data Type Values table in the data type manager.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def translateRecord(self, rec: db.DBRecord) -> db.DBRecord: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

