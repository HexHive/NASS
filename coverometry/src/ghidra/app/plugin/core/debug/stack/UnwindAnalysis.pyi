import ghidra.app.plugin.core.debug.stack
import ghidra.program.model.address
import ghidra.util.task
import java.lang


class UnwindAnalysis(object):




    def __init__(self, __a0: ghidra.program.model.listing.Program): ...



    def computeUnwindInfo(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.util.task.TaskMonitor) -> ghidra.app.plugin.core.debug.stack.UnwindInfo: ...

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

