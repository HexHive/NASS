import ghidra.app.util.bin.format.golang.structmapping
import java.lang
import java.util


class StructureMarkup(object):
    """
    Optional interface that structure mapped classes can implement that allows them to control how
     their class is marked up.
 
     TODO: possibly refactor these methods to take a StructureContext parameter, which will
     allow removing the getStructureContext method.
    """









    def additionalMarkup(self, session: ghidra.app.util.bin.format.golang.structmapping.MarkupSession) -> None:
        """
        Called to allow the implementor to perform custom markup of itself.
        @param session state and methods to assist marking up the program
        @throws IOException if error during markup
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getExternalInstancesToMarkup(self) -> java.util.List:
        """
        Returns a list of items that should be recursively marked up.
        @return list of structure mapped object instances that should be marked up
        @throws IOException if error getting instances
        """
        ...

    def getStructureContext(self) -> ghidra.app.util.bin.format.golang.structmapping.StructureContext: ...

    def getStructureLabel(self) -> unicode:
        """
        Returns a string that can be used to place a label on the instance.
        @return string to be used as a labe, or null if there is not a valid label for the instance
        @throws IOException if error getting label
        """
        ...

    def getStructureName(self) -> unicode:
        """
        Returns the name of the instance, typically retrieved from data found inside the instance.
        @return string name, or null if this instance does not have a name
        @throws IOException if error getting name
        """
        ...

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

    @property
    def externalInstancesToMarkup(self) -> List[object]: ...

    @property
    def structureContext(self) -> ghidra.app.util.bin.format.golang.structmapping.StructureContext: ...

    @property
    def structureLabel(self) -> unicode: ...

    @property
    def structureName(self) -> unicode: ...