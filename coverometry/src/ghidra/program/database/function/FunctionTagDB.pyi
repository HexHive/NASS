import ghidra.program.database
import ghidra.program.model.listing
import ghidra.util
import java.lang


class FunctionTagDB(ghidra.program.database.DatabaseObject, ghidra.program.model.listing.FunctionTag):
    """
    Database object for FunctionTagAdapter objects.
    """





    def __init__(self, mgr: ghidra.program.database.function.FunctionTagManagerDB, cache: ghidra.program.database.DBObjectCache, record: db.DBRecord): ...



    @overload
    def compareTo(self, otherTag: ghidra.program.model.listing.FunctionTag) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def delete(self) -> None: ...

    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComment(self) -> unicode: ...

    def getId(self) -> long: ...

    def getKey(self) -> long:
        """
        Get the database key for this object.
        """
        ...

    def getName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isDeleted(self, lock: ghidra.util.Lock) -> bool:
        """
        Returns true if this object has been deleted. Note: once an object has been deleted, it will
         never be "refreshed". For example, if an object is ever deleted and is resurrected via an
         "undo", you will have get a fresh instance of the object.
        @param lock object cache lock object
        @return true if this object has been deleted.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setComment(self, comment: unicode) -> None: ...

    def setInvalid(self) -> None:
        """
        Invalidate this object. This does not necessarily mean that this object can never be used
         again. If the object can refresh itself, it may still be useable.
        """
        ...

    def setName(self, name: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def comment(self) -> unicode: ...

    @comment.setter
    def comment(self, value: unicode) -> None: ...

    @property
    def id(self) -> long: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...