import ghidra.program.model.address
import ghidra.program.model.listing
import java.lang


class VariableStorageManager(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getVariableStorageAddress(self, storage: ghidra.program.model.listing.VariableStorage, create: bool) -> ghidra.program.model.address.Address:
        """
        Get a variable address for the given storage specification.
        @param storage variable storage specification
        @param create if true a new variable address will be allocated if needed
        @return variable address which corresponds to the storage specification or null if not found
         and create is false.
        @throws IOException if an IO error occurs
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

