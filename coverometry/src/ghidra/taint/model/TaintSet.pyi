from typing import List
import ghidra.taint.model
import java.lang
import java.util


class TaintSet(object):
    EMPTY: ghidra.taint.model.TaintSet = 







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getMarks(self) -> java.util.Set: ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def of(__a0: List[ghidra.taint.model.TaintMark]) -> ghidra.taint.model.TaintSet: ...

    @staticmethod
    def parse(__a0: unicode) -> ghidra.taint.model.TaintSet: ...

    def tagged(self, __a0: unicode) -> ghidra.taint.model.TaintSet: ...

    def toString(self) -> unicode: ...

    def union(self, __a0: ghidra.taint.model.TaintSet) -> ghidra.taint.model.TaintSet: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def empty(self) -> bool: ...

    @property
    def marks(self) -> java.util.Set: ...