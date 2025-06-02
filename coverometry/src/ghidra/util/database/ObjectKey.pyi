import ghidra.util.database
import java.lang


class ObjectKey(object, java.lang.Comparable):




    def __init__(self, __a0: db.Table, __a1: long): ...



    @overload
    def compareTo(self, __a0: ghidra.util.database.ObjectKey) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

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

