from typing import List
import ghidra.trace.model.memory
import java.lang
import java.util


class TraceMemoryFlag(java.lang.Enum):
    EXECUTE: ghidra.trace.model.memory.TraceMemoryFlag = EXECUTE
    READ: ghidra.trace.model.memory.TraceMemoryFlag = READ
    VOLATILE: ghidra.trace.model.memory.TraceMemoryFlag = VOLATILE
    WRITE: ghidra.trace.model.memory.TraceMemoryFlag = WRITE







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    @staticmethod
    def fromBits(__a0: int) -> java.util.Collection: ...

    @overload
    @staticmethod
    def fromBits(__a0: java.util.EnumSet, __a1: int) -> java.util.EnumSet: ...

    def getBits(self) -> int: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def toBits(__a0: java.util.Collection) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.trace.model.memory.TraceMemoryFlag: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.trace.model.memory.TraceMemoryFlag]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def bits(self) -> int: ...