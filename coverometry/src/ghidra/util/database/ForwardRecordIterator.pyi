import db
import ghidra.util.database
import java.lang


class ForwardRecordIterator(ghidra.util.database.AbstractDirectedRecordIterator):




    def __init__(self, __a0: db.RecordIterator): ...



    def delete(self) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getIndexIterator(__a0: db.Table, __a1: int, __a2: ghidra.util.database.FieldSpan, __a3: ghidra.util.database.DirectedIterator.Direction) -> ghidra.util.database.DirectedRecordIterator: ...

    @staticmethod
    def getIterator(__a0: db.Table, __a1: ghidra.util.database.KeySpan, __a2: ghidra.util.database.DirectedIterator.Direction) -> ghidra.util.database.DirectedRecordIterator: ...

    def hasNext(self) -> bool: ...

    def hashCode(self) -> int: ...

    def next(self) -> object: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

