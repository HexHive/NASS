from typing import Iterator
import ghidra.program.model.listing
import java.lang
import java.util
import java.util.function


class CodeUnitKeyIterator(object, ghidra.program.model.listing.CodeUnitIterator):
    """
    Converts an AddressKeyIterator into a CodeUnitIterator
    """

    EMPTY_ITERATOR: ghidra.program.model.listing.CodeUnitIterator = ghidra.program.model.listing.CodeUnitIterator$1@67c5e50c



    def __init__(self, codeMgr: ghidra.program.database.code.CodeManager, it: ghidra.program.database.map.AddressKeyIterator, forward: bool):
        """
        Construct a new CodeUnitKeyIterator
        @param codeMgr the code manager
        @param it the addressKeyIterator
        @param forward the direction to iterate.
        """
        ...

    def __iter__(self) -> Iterator[ghidra.program.model.listing.CodeUnit]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def forEachRemaining(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool:
        """
        @see ghidra.program.model.listing.CodeUnitIterator#hasNext()
        """
        ...

    def hashCode(self) -> int: ...

    def iterator(self) -> Iterator[ghidra.program.model.listing.CodeUnit]: ...

    def next(self) -> ghidra.program.model.listing.CodeUnit:
        """
        @see ghidra.program.model.listing.CodeUnitIterator#next()
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def remove(self) -> None:
        """
        @see java.util.Iterator#remove()
        """
        ...

    def spliterator(self) -> java.util.Spliterator: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

