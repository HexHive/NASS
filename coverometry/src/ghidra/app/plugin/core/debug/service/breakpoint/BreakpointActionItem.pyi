import ghidra.program.model.address
import java.lang
import java.util.concurrent


class BreakpointActionItem(object):








    def equals(self, __a0: object) -> bool: ...

    def execute(self) -> java.util.concurrent.CompletableFuture: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def range(self, __a0: ghidra.program.model.address.Address, __a1: long) -> ghidra.program.model.address.AddressRange: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

