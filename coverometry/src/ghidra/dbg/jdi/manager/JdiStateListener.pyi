import ghidra.dbg.jdi.manager
import ghidra.util
import java.lang


class JdiStateListener(ghidra.util.TriConsumer, object):








    @overload
    def accept(self, __a0: int, __a1: int, __a2: ghidra.dbg.jdi.manager.JdiCause) -> None: ...

    @overload
    def accept(self, __a0: object, __a1: object, __a2: object) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def stateChanged(self, __a0: int, __a1: ghidra.dbg.jdi.manager.JdiCause) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

