import ghidra.program.model.listing
import java.lang
import java.util


class FunctionTagManager(object):
    """
    Interface for managing function tags. Tags are simple objects consisting of a name and an 
     optional comment, which can be applied to functions.
 
     See ghidra.program.database.function.FunctionTagAdapter 
     See ghidra.program.database.function.FunctionTagMappingAdapter
    """









    def createFunctionTag(self, name: unicode, comment: unicode) -> ghidra.program.model.listing.FunctionTag:
        """
        Creates a new function tag with the given attributes if one does
         not already exist. Otherwise, returns the existing tag.
        @param name the tag name
        @param comment the comment associated with the tag (optional)
        @return the new function tag
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAllFunctionTags(self) -> java.util.List:
        """
        Returns all function tags in the database
        @return list of function tags
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getFunctionTag(self, id: long) -> ghidra.program.model.listing.FunctionTag:
        """
        Returns the function tag with the given database id
        @param id the tags database id
        @return the function tag, or null if not found
        """
        ...

    @overload
    def getFunctionTag(self, name: unicode) -> ghidra.program.model.listing.FunctionTag:
        """
        Returns the function tag with the given name
        @param name the tag name
        @return the function tag, or null if not found
        """
        ...

    def getUseCount(self, tag: ghidra.program.model.listing.FunctionTag) -> int:
        """
        Returns the number of times the given tag has been applied to a function
        @param tag the tag
        @return the count
        """
        ...

    def hashCode(self) -> int: ...

    def isTagAssigned(self, name: unicode) -> bool:
        """
        Returns true if the given tag is assigned to a function
        @param name the tag name
        @return true if assigned to a function
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

    @property
    def allFunctionTags(self) -> List[object]: ...