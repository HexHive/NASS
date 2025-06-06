from typing import Iterator
import ghidra.program.model.address
import java.lang
import java.util
import java.util.function


class IndexToAddressRangeIteratorAdapter(object, ghidra.program.model.address.AddressRangeIterator):




    def __init__(self, addressMap: ghidra.program.database.map.AddressMap, it: ghidra.util.datastruct.IndexRangeIterator):
        """
        Constructs a new IndexToAddressRangeIteratorAdapter given an AddressMap and 
         IndexRangeIterator
        @param addressMap the address map
        @param it the IndexRangeIterator
        """
        ...

    def __iter__(self) -> Iterator[ghidra.program.model.address.AddressRange]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def forEachRemaining(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool:
        """
        @see ghidra.program.model.address.AddressRangeIterator#hasNext()
        """
        ...

    def hashCode(self) -> int: ...

    def iterator(self) -> Iterator[ghidra.program.model.address.AddressRange]: ...

    def next(self) -> ghidra.program.model.address.AddressRange:
        """
        @see ghidra.program.model.address.AddressRangeIterator#next()
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

