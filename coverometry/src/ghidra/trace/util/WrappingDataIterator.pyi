from typing import Iterator
from typing import List
import ghidra.program.model.listing
import java.lang
import java.util
import java.util.function


class WrappingDataIterator(object, ghidra.program.model.listing.DataIterator):
    EMPTY: ghidra.program.model.listing.DataIterator = ghidra.program.model.listing.DataIterator$IteratorWrapper@23958aa0



    def __init__(self, __a0: java.util.Iterator): ...

    def __iter__(self) -> Iterator[object]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def forEachRemaining(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool: ...

    def hashCode(self) -> int: ...

    def iterator(self) -> java.util.Iterator: ...

    def next(self) -> object: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def of(__a0: List[ghidra.program.model.listing.Data]) -> ghidra.program.model.listing.DataIterator: ...

    def remove(self) -> None: ...

    def spliterator(self) -> java.util.Spliterator: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

