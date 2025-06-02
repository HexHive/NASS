import db
import ghidra.program.database.module
import java.lang


class ModuleDBAdapterV0(ghidra.program.database.module.ModuleDBAdapter, db.RecordTranslator):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def translateRecord(self, oldRec: db.DBRecord) -> db.DBRecord: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

