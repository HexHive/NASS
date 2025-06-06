from typing import Iterator
import generic.util
import java.lang
import java.util.function


class AbstractPeekableIterator(object, generic.util.PeekableIterator):




    def __init__(self): ...

    def __iter__(self) -> Iterator[object]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEachRemaining(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool: ...

    def hashCode(self) -> int: ...

    def next(self) -> object: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def peek(self) -> object: ...

    def remove(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

