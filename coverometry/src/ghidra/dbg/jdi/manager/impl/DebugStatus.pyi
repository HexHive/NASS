from typing import List
import ghidra.dbg.jdi.manager.impl
import java.lang
import java.util


class DebugStatus(java.lang.Enum):
    BREAK: ghidra.dbg.jdi.manager.impl.DebugStatus = BREAK
    GO: ghidra.dbg.jdi.manager.impl.DebugStatus = GO
    IGNORE_EVENT: ghidra.dbg.jdi.manager.impl.DebugStatus = IGNORE_EVENT
    INSIDE_WAIT: long = 0x100000000L
    MASK: long = 0xafL
    NO_CHANGE: ghidra.dbg.jdi.manager.impl.DebugStatus = NO_CHANGE
    NO_DEBUGGEE: ghidra.dbg.jdi.manager.impl.DebugStatus = NO_DEBUGGEE
    OUT_OF_SYNC: ghidra.dbg.jdi.manager.impl.DebugStatus = OUT_OF_SYNC
    RESTART_REQUESTED: ghidra.dbg.jdi.manager.impl.DebugStatus = RESTART_REQUESTED
    STEP_BRANCH: ghidra.dbg.jdi.manager.impl.DebugStatus = STEP_BRANCH
    STEP_INTO: ghidra.dbg.jdi.manager.impl.DebugStatus = STEP_INTO
    STEP_OVER: ghidra.dbg.jdi.manager.impl.DebugStatus = STEP_OVER
    TIMEOUT: ghidra.dbg.jdi.manager.impl.DebugStatus = TIMEOUT
    WAIT_INPUT: ghidra.dbg.jdi.manager.impl.DebugStatus = WAIT_INPUT
    WAIT_TIMEOUT: long = 0x200000000L
    precedence: int
    shouldWait: bool
    threadState: int







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromArgument(__a0: long) -> ghidra.dbg.jdi.manager.impl.DebugStatus: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isInsideWait(__a0: long) -> bool: ...

    @staticmethod
    def isWaitTimeout(__a0: long) -> bool: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def update(__a0: ghidra.dbg.jdi.manager.impl.DebugStatus) -> ghidra.dbg.jdi.manager.impl.DebugStatus: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.dbg.jdi.manager.impl.DebugStatus: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.dbg.jdi.manager.impl.DebugStatus]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

