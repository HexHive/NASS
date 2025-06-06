from typing import Iterator
import ghidra.program.model.symbol
import java.lang
import java.util
import java.util.function


class SymbolIterator(java.util.Iterator, java.lang.Iterable, object):
    """
    Iterator defined to return Symbol objects.
    """

    EMPTY_ITERATOR: ghidra.program.model.symbol.SymbolIterator = ghidra.program.model.symbol.SymbolIterator$1@40f7c6c3





    def __iter__(self) -> Iterator[ghidra.program.model.symbol.Symbol]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def forEachRemaining(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool:
        """
        Return true if there is a next symbol.
        """
        ...

    def hashCode(self) -> int: ...

    def iterator(self) -> java.util.Iterator: ...

    def next(self) -> ghidra.program.model.symbol.Symbol:
        """
        Get the next symbol or null if no more symbols.
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

