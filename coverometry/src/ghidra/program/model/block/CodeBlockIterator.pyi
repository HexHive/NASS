from typing import Iterator
import ghidra.program.model.block
import java.lang
import java.util
import java.util.function


class CodeBlockIterator(java.lang.Iterable, object):
    """
    An iterator interface over CodeBlocks.
 
     Note: this iterator is also Iterable.  The #hasNext() and #next()
     methods of this interface throw a CancelledException if the monitor is cancelled.  The
     iterator returned from #iterator() does not throw a cancelled exception.  If 
     you need to know the cancelled state of this iterator, then you must check the cancelled state
     of the monitor passed into this iterator via the CodeBlockModel.  See 
     TaskMonitor#isCancelled().
    """







    def __iter__(self) -> Iterator[ghidra.program.model.block.CodeBlock]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool:
        """
        Return true if next() will return a CodeBlock.
        @return true if next() will return a CodeBlock.
        @throws CancelledException thrown if the operation is cancelled.
        """
        ...

    def hashCode(self) -> int: ...

    def iterator(self) -> Iterator[ghidra.program.model.block.CodeBlock]: ...

    def next(self) -> ghidra.program.model.block.CodeBlock:
        """
        Return the next CodeBlock.
        @return the next CodeBlock.
        @throws CancelledException thrown if the operation is cancelled.
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

