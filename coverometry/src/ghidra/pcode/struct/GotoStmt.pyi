import ghidra.pcode.struct
import java.lang


class GotoStmt(ghidra.pcode.struct.AbstractStmt):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getContext(self) -> ghidra.pcode.struct.StructuredSleigh: ...

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
    def context(self) -> ghidra.pcode.struct.StructuredSleigh: ...