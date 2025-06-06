from typing import Iterator
from typing import List
import ghidra.app.plugin.core.debug.stack
import java.lang
import java.util
import java.util.function
import java.util.stream


class StackUnwindWarningSet(object, java.util.Collection):




    @overload
    def __init__(self): ...

    @overload
    def __init__(self, __a0: List[ghidra.app.plugin.core.debug.stack.StackUnwindWarning]): ...

    @overload
    def __init__(self, __a0: java.util.Collection): ...

    def __iter__(self): ...

    @overload
    def add(self, __a0: ghidra.app.plugin.core.debug.stack.StackUnwindWarning) -> bool: ...

    @overload
    def add(self, __a0: object) -> bool: ...

    def addAll(self, __a0: java.util.Collection) -> bool: ...

    def clear(self) -> None: ...

    def contains(self, __a0: object) -> bool: ...

    def containsAll(self, __a0: java.util.Collection) -> bool: ...

    @staticmethod
    def custom(__a0: unicode) -> ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    def iterator(self) -> java.util.Iterator: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parallelStream(self) -> java.util.stream.Stream: ...

    def remove(self, __a0: object) -> bool: ...

    def removeAll(self, __a0: java.util.Collection) -> bool: ...

    def removeIf(self, __a0: java.util.function.Predicate) -> bool: ...

    def reportDetails(self) -> None: ...

    def retainAll(self, __a0: java.util.Collection) -> bool: ...

    def size(self) -> int: ...

    def spliterator(self) -> java.util.Spliterator: ...

    def stream(self) -> java.util.stream.Stream: ...

    def summarize(self) -> List[object]: ...

    @overload
    def toArray(self) -> List[object]: ...

    @overload
    def toArray(self, __a0: List[object]) -> List[object]: ...

    @overload
    def toArray(self, __a0: java.util.function.IntFunction) -> List[object]: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def empty(self) -> bool: ...