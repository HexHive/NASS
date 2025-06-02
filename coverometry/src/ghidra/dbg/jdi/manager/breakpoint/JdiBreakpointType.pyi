from typing import List
import ghidra.dbg.jdi.manager.breakpoint
import java.lang
import java.util


class JdiBreakpointType(java.lang.Enum):
    ACCESS_WATCHPOINT: ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointType = access watchpont
    BREAKPOINT: ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointType = breakpoint
    BY_NAME: java.util.Map = {u'modification watchpoint': modification watchpoint, u'access watchpont': access watchpont, u'<OTHER>': <OTHER>, u'breakpoint': breakpoint}
    MODIFICATION_WATCHPOINT: ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointType = modification watchpoint
    OTHER: ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointType = <OTHER>







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromStr(__a0: unicode) -> ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointType: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isWatchpoint(self) -> bool: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointType: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointType]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def watchpoint(self) -> bool: ...