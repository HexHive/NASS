import ghidra.dbg.target
import ghidra.program.model.address
import java.lang


class DebuggerObjectModelWithMemory(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getMemory(self, __a0: ghidra.dbg.target.TargetObject, __a1: ghidra.program.model.address.Address, __a2: int) -> ghidra.dbg.target.TargetMemory: ...

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

