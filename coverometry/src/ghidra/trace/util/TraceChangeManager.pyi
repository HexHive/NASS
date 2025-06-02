import ghidra.trace.util
import java.lang


class TraceChangeManager(object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setChanged(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def changed(self) -> None: ...  # No getter available.

    @changed.setter
    def changed(self, value: ghidra.trace.util.TraceChangeRecord) -> None: ...