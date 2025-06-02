from typing import List
import ghidra.util
import java.lang
import java.util


class ComparatorMath(java.lang.Enum):








    @overload
    @staticmethod
    def cmax(__a0: java.lang.Comparable, __a1: java.lang.Comparable) -> java.lang.Comparable: ...

    @overload
    @staticmethod
    def cmax(__a0: object, __a1: object, __a2: java.util.Comparator) -> object: ...

    @overload
    @staticmethod
    def cmin(__a0: java.lang.Comparable, __a1: java.lang.Comparable) -> java.lang.Comparable: ...

    @overload
    @staticmethod
    def cmin(__a0: object, __a1: object, __a2: java.util.Comparator) -> object: ...

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
    def valueOf(__a0: unicode) -> ghidra.util.ComparatorMath: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.util.ComparatorMath]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

