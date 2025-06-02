import ghidra.program.model.listing
import ghidra.util.task
import java.lang


class FunctionHasher(object):








    def commonBitCount(self, funcA: ghidra.program.model.listing.Function, funcB: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hash(self, function: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor) -> long: ...

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

