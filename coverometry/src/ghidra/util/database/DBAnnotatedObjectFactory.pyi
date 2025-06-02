import db
import ghidra.util.database
import java.lang


class DBAnnotatedObjectFactory(object):








    def create(self, __a0: ghidra.util.database.DBCachedObjectStore, __a1: db.DBRecord) -> ghidra.util.database.DBAnnotatedObject: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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

