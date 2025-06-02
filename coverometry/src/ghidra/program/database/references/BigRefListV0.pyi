import ghidra.program.database.references
import ghidra.util
import java.lang


class BigRefListV0(ghidra.program.database.references.RefList):
    """
    To change the template for this generated type comment go to
     WindowPreferencesJavaCode GenerationCode and Comments
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getKey(self) -> long:
        """
        Get the database key for this object.
        """
        ...

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

    def setInvalid(self) -> None:
        """
        Invalidate this object. This does not necessarily mean that this object can never be used
         again. If the object can refresh itself, it may still be useable.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

