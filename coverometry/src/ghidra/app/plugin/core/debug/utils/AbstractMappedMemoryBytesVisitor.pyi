import ghidra.program.model.address
import ghidra.trace.model
import java.lang


class AbstractMappedMemoryBytesVisitor(object):




    def __init__(self, __a0: ghidra.app.services.DebuggerStaticMappingService, __a1: List[int]): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def visit(self, __a0: ghidra.trace.model.Trace, __a1: long, __a2: ghidra.program.model.address.AddressSetView) -> bool: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

