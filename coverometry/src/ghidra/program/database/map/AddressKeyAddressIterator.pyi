from typing import Iterator
import ghidra.program.model.address
import java.lang
import java.util
import java.util.function


class AddressKeyAddressIterator(object, ghidra.program.model.address.AddressIterator):
    """
    Converts an AddressKeyIterator or an addressKeyAddressIterator into an AddressIterator
    """

    EMPTY_ITERATOR: ghidra.program.model.address.AddressIterator = ghidra.program.model.address.AddressIterator$1@7624adae



    def __init__(self, keyIter: db.DBLongIterator, forward: bool, addrMap: ghidra.program.database.map.AddressMap, errHandler: db.util.ErrorHandler):
        """
        Constructor.
        @param keyIter address key iterator, may be null.  All long values must decode properly with the specified addrMap.
        @param forward true to iterate in the direction of increasing addresses.
        @param addrMap address map
        @param errHandler IO error handler (may be null)
        """
        ...

    def __iter__(self) -> Iterator[ghidra.program.model.address.Address]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def forEachRemaining(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool:
        """
        @see ghidra.program.model.address.AddressIterator#hasNext()
        """
        ...

    def hashCode(self) -> int: ...

    def iterator(self) -> Iterator[ghidra.program.model.address.Address]: ...

    def next(self) -> ghidra.program.model.address.Address:
        """
        @see ghidra.program.model.address.AddressIterator#next()
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

