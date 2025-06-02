import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class ImageRuntimeFunctionEntries(object):
    """
    An interface for working with function table entries used for exception handling, which are found
     in the .pdata section.  The actual implementations are architecture-specific.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def markup(self, program: ghidra.program.model.listing.Program, start: ghidra.program.model.address.Address) -> None:
        """
        Marks up an {@link ImageRuntimeFunctionEntries}
        @param program The {@link Program}
        @param start The start {@link Address}
        @throws IOException If there was an IO-related error creating the data
        @throws DuplicateNameException If a data type of the same name already exists
        @throws CodeUnitInsertionException If data creation failed
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

