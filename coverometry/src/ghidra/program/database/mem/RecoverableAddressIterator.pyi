from typing import Iterator
import ghidra.program.model.address
import java.lang
import java.util
import java.util.function


class RecoverableAddressIterator(object, ghidra.program.model.address.AddressIterator):
    """
    RecoverableAddressIterator provides the ability to iterator over an AddressSet
     which is getting modified concurrent with the iteration of Addresses contained within it.  Do to 
     multiple levels of prefetch caching, the results returned may be stale relative to the actual
     AddressSet at any point in time.  The primary intent is to return addresses in proper order
     and avoid throwing a ConcurrentModificationException which the standard iterators are
     subject to.
 
     NOTES:
 
     The iterator methods are not symchronized but could be made so if restricted to 
     use in conjunction with the SynchronizedAddressSet where it would synchronize on 
     the set itself.
     This class and SynchronizedAddressSet could be made public alongside AddressSet
     if so desired in the future.  Its current use has been limited until proven to be thread-safe
     and useful.
 
    """







    def __iter__(self) -> Iterator[ghidra.program.model.address.Address]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def forEachRemaining(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool: ...

    def hashCode(self) -> int: ...

    def iterator(self) -> Iterator[ghidra.program.model.address.Address]: ...

    def next(self) -> ghidra.program.model.address.Address: ...

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

