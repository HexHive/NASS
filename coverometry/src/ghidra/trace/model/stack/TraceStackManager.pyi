import ghidra.program.model.address
import ghidra.trace.model.stack
import ghidra.trace.model.thread
import java.lang


class TraceStackManager(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFramesIn(self, __a0: ghidra.program.model.address.AddressSetView) -> java.lang.Iterable: ...

    def getLatestStack(self, __a0: ghidra.trace.model.thread.TraceThread, __a1: long) -> ghidra.trace.model.stack.TraceStack: ...

    def getStack(self, __a0: ghidra.trace.model.thread.TraceThread, __a1: long, __a2: bool) -> ghidra.trace.model.stack.TraceStack: ...

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

