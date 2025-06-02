import ghidra.app.util.bin.format.dwarf4.external
import ghidra.program.model.listing
import java.lang


class SearchLocationCreatorContext(object):
    """
    Information outside of a location string that might be needed to create a new SearchLocation
     instance.
    """





    def __init__(self, registry: ghidra.app.util.bin.format.dwarf4.external.SearchLocationRegistry, program: ghidra.program.model.listing.Program):
        """
        Create a new context object with references to the registry and the current program.
        @param registry {@link SearchLocationRegistry}
        @param program the current {@link Program}
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        @return the current {@link Program}
        """
        ...

    def getRegistry(self) -> ghidra.app.util.bin.format.dwarf4.external.SearchLocationRegistry:
        """
        @return the {@link SearchLocationRegistry} that is creating the {@link SearchLocation}
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
    def program(self) -> ghidra.program.model.listing.Program: ...

    @property
    def registry(self) -> ghidra.app.util.bin.format.dwarf4.external.SearchLocationRegistry: ...