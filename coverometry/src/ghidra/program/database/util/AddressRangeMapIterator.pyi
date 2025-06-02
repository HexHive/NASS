from typing import Iterator
import ghidra.program.model.address
import java.lang
import java.util
import java.util.function


class AddressRangeMapIterator(object, ghidra.program.model.address.AddressRangeIterator):
    """
    An iterator over ranges that have a defined values in the AddressRangeMapDB
 
     NOTE: this iterator is complicated by the fact that there can exist a record that represents
     an address range that "wraps around" from the max address to the 0 address, where this record
     actually represents two address ranges. This is cause by changing the image base which shifts
     all records up or down. That shift can cause a record to have a wrapping range where the start
     address is larger than the end address. If such a record exists, it is found during construction
     and the lower address range is extracted from the record and is stored as a special "start range"
     that should be emitted before any other ranges in that space. The upper range of a wrapping
     record will be handled more naturally during the iteration process. When a wrapping record is
     encountered during the normal iteration, only the upper range is used and it will be in the
     correct address range ordering.
    """







    def __iter__(self) -> Iterator[ghidra.program.model.address.AddressRange]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def forEachRemaining(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool: ...

    def hashCode(self) -> int: ...

    def iterator(self) -> Iterator[ghidra.program.model.address.AddressRange]: ...

    def next(self) -> ghidra.program.model.address.AddressRange: ...

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

