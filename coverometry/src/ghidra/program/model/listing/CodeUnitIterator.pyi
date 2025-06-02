from typing import Iterator
import ghidra.program.model.listing
import java.lang
import java.util
import java.util.function


class CodeUnitIterator(java.util.Iterator, java.lang.Iterable, object):
    """
    Interface to define an iterator over over some set of  code units.
    """

    EMPTY_ITERATOR: ghidra.program.model.listing.CodeUnitIterator = ghidra.program.model.listing.CodeUnitIterator$1@67c5e50c





    def __iter__(self) -> Iterator[ghidra.program.model.listing.CodeUnit]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def forEachRemaining(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool:
        """
        Return true if there is a next CodeUnit.
        """
        ...

    def hashCode(self) -> int: ...

    def iterator(self) -> java.util.Iterator: ...

    def next(self) -> ghidra.program.model.listing.CodeUnit:
        """
        Get the next CodeUnit or null if no more CodeUnits.
         <P>NOTE: This deviates from the standard {@link Iterator} interface
         by returning null instead of throwing an exception.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def remove(self) -> None: ...

    def spliterator(self) -> java.util.Spliterator: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

