from typing import List
import ghidra.framework
import java.lang
import java.util


class OperatingSystem(java.lang.Enum):
    CURRENT_OPERATING_SYSTEM: ghidra.framework.OperatingSystem = LINUX(Linux)
    LINUX: ghidra.framework.OperatingSystem = LINUX(Linux)
    MAC_OS_X: ghidra.framework.OperatingSystem = MAC_OS_X(Linux)
    UNSUPPORTED: ghidra.framework.OperatingSystem = UNSUPPORTED(Linux)
    WINDOWS: ghidra.framework.OperatingSystem = WINDOWS(Linux)







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
    def valueOf(__a0: unicode) -> ghidra.framework.OperatingSystem: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.framework.OperatingSystem]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

