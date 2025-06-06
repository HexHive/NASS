from typing import List
import ghidra.feature.vt.gui.provider.functionassociation
import java.lang
import java.util


class FilterSettings(java.lang.Enum):
    SHOW_ALL: ghidra.feature.vt.gui.provider.functionassociation.FilterSettings = SHOW_ALL
    SHOW_UNACCEPTED: ghidra.feature.vt.gui.provider.functionassociation.FilterSettings = SHOW_UNACCEPTED
    SHOW_UNMATCHED: ghidra.feature.vt.gui.provider.functionassociation.FilterSettings = SHOW_UNMATCHED







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
    def valueOf(__a0: unicode) -> ghidra.feature.vt.gui.provider.functionassociation.FilterSettings: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.feature.vt.gui.provider.functionassociation.FilterSettings]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

