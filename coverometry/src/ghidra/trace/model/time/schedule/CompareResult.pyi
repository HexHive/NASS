from typing import List
import ghidra.trace.model.time.schedule
import java.lang
import java.util


class CompareResult(java.lang.Enum):
    EQUALS: ghidra.trace.model.time.schedule.CompareResult = EQUALS
    REL_GT: ghidra.trace.model.time.schedule.CompareResult = REL_GT
    REL_LT: ghidra.trace.model.time.schedule.CompareResult = REL_LT
    UNREL_GT: ghidra.trace.model.time.schedule.CompareResult = UNREL_GT
    UNREL_LT: ghidra.trace.model.time.schedule.CompareResult = UNREL_LT
    compareTo: int







    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def related(__a0: int) -> ghidra.trace.model.time.schedule.CompareResult: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def unrelated(__a0: int) -> ghidra.trace.model.time.schedule.CompareResult: ...

    @overload
    @staticmethod
    def unrelated(__a0: ghidra.trace.model.time.schedule.CompareResult) -> ghidra.trace.model.time.schedule.CompareResult: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.trace.model.time.schedule.CompareResult: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.trace.model.time.schedule.CompareResult]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

