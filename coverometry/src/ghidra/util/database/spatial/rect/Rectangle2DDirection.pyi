from typing import List
import ghidra.util.database.spatial.rect
import java.lang
import java.util


class Rectangle2DDirection(java.lang.Enum):
    BOTTOMMOST: ghidra.util.database.spatial.rect.Rectangle2DDirection = BOTTOMMOST
    LEFTMOST: ghidra.util.database.spatial.rect.Rectangle2DDirection = LEFTMOST
    RIGHTMOST: ghidra.util.database.spatial.rect.Rectangle2DDirection = RIGHTMOST
    TOPMOST: ghidra.util.database.spatial.rect.Rectangle2DDirection = TOPMOST







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isReversed(self) -> bool: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.util.database.spatial.rect.Rectangle2DDirection: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.util.database.spatial.rect.Rectangle2DDirection]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def reversed(self) -> bool: ...