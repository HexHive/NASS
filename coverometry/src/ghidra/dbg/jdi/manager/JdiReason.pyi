from typing import List
import ghidra.dbg.jdi.manager
import java.lang
import java.util


class JdiReason(object):





    class Reasons(java.lang.Enum, ghidra.dbg.jdi.manager.JdiReason):
        ACCESS_WATCHPOINT_HIT: ghidra.dbg.jdi.manager.JdiReason.Reasons = ACCESS_WATCHPOINT_HIT
        BREAKPOINT_HIT: ghidra.dbg.jdi.manager.JdiReason.Reasons = BREAKPOINT_HIT
        INTERRUPT: ghidra.dbg.jdi.manager.JdiReason.Reasons = INTERRUPT
        NONE: ghidra.dbg.jdi.manager.JdiReason.Reasons = NONE
        RESUMED: ghidra.dbg.jdi.manager.JdiReason.Reasons = RESUMED
        STEP: ghidra.dbg.jdi.manager.JdiReason.Reasons = STEP
        UNKNOWN: ghidra.dbg.jdi.manager.JdiReason.Reasons = UNKNOWN
        WATCHPOINT_HIT: ghidra.dbg.jdi.manager.JdiReason.Reasons = WATCHPOINT_HIT







        @overload
        def compareTo(self, __a0: java.lang.Enum) -> int: ...

        @overload
        def compareTo(self, __a0: object) -> int: ...

        def desc(self) -> unicode: ...

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
        def valueOf(__a0: unicode) -> ghidra.dbg.jdi.manager.JdiReason.Reasons: ...

        @overload
        @staticmethod
        def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

        @staticmethod
        def values() -> List[ghidra.dbg.jdi.manager.JdiReason.Reasons]: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...







    def desc(self) -> unicode: ...

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

