from typing import List
import ghidra.app.plugin.processors.sleigh
import java.lang
import java.util


class UniqueLayout(java.lang.Enum):
    ANALYSIS: ghidra.app.plugin.processors.sleigh.UniqueLayout = ANALYSIS
    INJECT: ghidra.app.plugin.processors.sleigh.UniqueLayout = INJECT
    RUNTIME_BITRANGE_EA: ghidra.app.plugin.processors.sleigh.UniqueLayout = RUNTIME_BITRANGE_EA
    RUNTIME_BOOLEAN_INVERT: ghidra.app.plugin.processors.sleigh.UniqueLayout = RUNTIME_BOOLEAN_INVERT
    RUNTIME_RETURN_LOCATION: ghidra.app.plugin.processors.sleigh.UniqueLayout = RUNTIME_RETURN_LOCATION
    SLEIGH_BASE: ghidra.app.plugin.processors.sleigh.UniqueLayout = SLEIGH_BASE







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def getOffset(self, __a0: ghidra.app.plugin.processors.sleigh.SleighLanguage) -> long: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.plugin.processors.sleigh.UniqueLayout: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.plugin.processors.sleigh.UniqueLayout]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

