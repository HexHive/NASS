from typing import Iterator
import ghidra.program.model.block
import java.lang
import java.util
import java.util.function


class MultEntSubIterator(object, ghidra.program.model.block.CodeBlockIterator):
    """
    MultEntSubIterator is an implementation of
     CodeBlockIterator capable of iterating in
     the forward direction over subroutine code blocks.
     The iterator supports subroutine models which allow one or
     more called/source entry points within a subroutine and do not
     share code with other subroutines produced by the same model.
    """







    def __iter__(self) -> Iterator[ghidra.program.model.block.CodeBlock]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool:
        """
        @see ghidra.program.model.block.CodeBlockIterator#hasNext()
        """
        ...

    def hashCode(self) -> int: ...

    def iterator(self) -> java.util.Iterator: ...

    def next(self) -> ghidra.program.model.block.CodeBlock:
        """
        @see ghidra.program.model.block.CodeBlockIterator#next()
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def spliterator(self) -> java.util.Spliterator: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

