from typing import List
import ghidra.app.plugin.core.debug.gui.thread
import java.lang
import java.util


class ThreadState(java.lang.Enum):
    ALIVE: ghidra.app.plugin.core.debug.gui.thread.ThreadState = ALIVE
    RUNNING: ghidra.app.plugin.core.debug.gui.thread.ThreadState = RUNNING
    STOPPED: ghidra.app.plugin.core.debug.gui.thread.ThreadState = STOPPED
    TERMINATED: ghidra.app.plugin.core.debug.gui.thread.ThreadState = TERMINATED
    UNKNOWN: ghidra.app.plugin.core.debug.gui.thread.ThreadState = UNKNOWN







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.plugin.core.debug.gui.thread.ThreadState: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.plugin.core.debug.gui.thread.ThreadState]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

