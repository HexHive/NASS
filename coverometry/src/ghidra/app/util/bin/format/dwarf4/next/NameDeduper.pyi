import java.lang
import java.util


class NameDeduper(object):
    """
    Helper for allocating unique string names.
 
     "Reserved names" are names that will be used by later calls to the de-duper.
 
     "Used names" are names that are already allocated and are in use.
 
     Reserved names only prevent re-use of a name when a name is being generated because of a
     collision with a "used name".
    """





    def __init__(self):
        """
        Create a new name de-duper.
        """
        ...



    def addReservedNames(self, additionalReservedNames: java.util.Collection) -> None:
        """
        Add names to the de-duper that will be used in a future call.  These names do not block
         calls to confirm that a name is unique, but instead prevent the name from being used
         when an auto-generated name is created.
        @param additionalReservedNames
        """
        ...

    def addUsedNames(self, alreadyUsedNames: java.util.Collection) -> None:
        """
        Add names to the the de-duper that have already been used.
        @param alreadyUsedNames
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getUniqueName(self, name: unicode) -> unicode:
        """
        Confirms that the specified name is unique, or returns a generated name that is unique.
        @param name name to test
        @return {@code null} if specified name is already unique (and marks the specified name as
         used), or returns a new, unique generated name
        """
        ...

    def hashCode(self) -> int: ...

    def isUniqueName(self, name: unicode) -> bool:
        """
        Returns true if the specified name hasn't been allocated yet.
        @param name
        @return 
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

