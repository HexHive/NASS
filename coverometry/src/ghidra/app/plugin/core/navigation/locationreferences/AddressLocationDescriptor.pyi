import ghidra.app.plugin.core.navigation.locationreferences
import java.lang


class AddressLocationDescriptor(ghidra.app.plugin.core.navigation.locationreferences.LocationDescriptor):








    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLabel(self) -> unicode: ...

    def getTypeName(self) -> unicode: ...

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

