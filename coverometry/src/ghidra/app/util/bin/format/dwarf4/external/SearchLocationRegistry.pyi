import ghidra.app.util.bin.format.dwarf4.external
import ghidra.app.util.bin.format.dwarf4.external.SearchLocationRegistry
import ghidra.program.model.listing
import java.lang
import java.util.function


class SearchLocationRegistry(object):
    """
    List of SearchLocation types that can be saved / restored from a configuration string.
    """






    class SearchLocationCreator(object):








        def create(self, __a0: unicode, __a1: ghidra.app.util.bin.format.dwarf4.external.SearchLocationCreatorContext) -> ghidra.app.util.bin.format.dwarf4.external.SearchLocation: ...

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



    def __init__(self, registerDefault: bool):
        """
        Creates a new registry, optionally registering the default SearchLocations.
        @param registerDefault boolean flag, if true register the built-in {@link SearchLocation}s
        """
        ...



    def createSearchLocation(self, locString: unicode, context: ghidra.app.util.bin.format.dwarf4.external.SearchLocationCreatorContext) -> ghidra.app.util.bin.format.dwarf4.external.SearchLocation:
        """
        Creates a {@link SearchLocation} using the provided location string.
        @param locString location string (previously returned by {@link SearchLocation#getName()}
        @param context a {@link SearchLocationCreatorContext context}
        @return new {@link SearchLocation} instance, or null if there are no registered matching
         SearchLocations
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @staticmethod
    def getInstance() -> ghidra.app.util.bin.format.dwarf4.external.SearchLocationRegistry: ...

    def hashCode(self) -> int: ...

    def newContext(self, program: ghidra.program.model.listing.Program) -> ghidra.app.util.bin.format.dwarf4.external.SearchLocationCreatorContext:
        """
        Creates a new {@link SearchLocationCreatorContext context}.
        @param program {@link Program}
        @return new {@link SearchLocationCreatorContext}
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def register(self, testFunc: java.util.function.Predicate, createFunc: ghidra.app.util.bin.format.dwarf4.external.SearchLocationRegistry.SearchLocationCreator) -> None:
        """
        Adds a {@link SearchLocation} to this registry.
        @param testFunc a {@link Predicate} that tests a location string, returning true if the
         string specifies the SearchLocation in question
        @param createFunc a {@link SearchLocationCreator} that will create a new {@link SearchLocation}
         instance given a location string and a {@link SearchLocationCreatorContext context}
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

