from typing import List
import ghidra.util.database.annotproc
import java.lang
import java.util


class AccessSpec(java.lang.Enum):
    PACKAGE: ghidra.util.database.annotproc.AccessSpec = PACKAGE
    PRIVATE: ghidra.util.database.annotproc.AccessSpec = PRIVATE
    PROTECTED: ghidra.util.database.annotproc.AccessSpec = PROTECTED
    PUBLIC: ghidra.util.database.annotproc.AccessSpec = PUBLIC







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def get(__a0: java.util.Set) -> ghidra.util.database.annotproc.AccessSpec: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isSameOrMorePermissive(__a0: ghidra.util.database.annotproc.AccessSpec, __a1: ghidra.util.database.annotproc.AccessSpec) -> bool: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.util.database.annotproc.AccessSpec: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.util.database.annotproc.AccessSpec]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

