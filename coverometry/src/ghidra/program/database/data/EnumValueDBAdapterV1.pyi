import db
import ghidra.program.database.data
import java.lang


class EnumValueDBAdapterV1(ghidra.program.database.data.EnumValueDBAdapter):
    """
    Version 1 implementation for the enumeration tables adapter.
 
     NOTE: Use of tablePrefix introduced with this adapter version.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def translateRecord(self, r: db.DBRecord) -> db.DBRecord: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

