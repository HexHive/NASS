from typing import Iterator
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.trace.util
import ghidra.util
import java.lang
import java.util
import java.util.function


class OverlappingObjectIterator(ghidra.util.AbstractPeekableIterator):
    ADDRESS_RANGE: ghidra.trace.util.OverlappingObjectIterator.AddressRangeRanger = ghidra.trace.util.OverlappingObjectIterator$AddressRangeRanger@12c4fffd
    CODE_UNIT: ghidra.trace.util.OverlappingObjectIterator.CodeUnitRanger = ghidra.trace.util.OverlappingObjectIterator$CodeUnitRanger@3ea26d1a
    SNAP_RANGE_KEY: ghidra.trace.util.OverlappingObjectIterator.SnapRangeKeyRanger = ghidra.trace.util.OverlappingObjectIterator$SnapRangeKeyRanger@5d11008b




    class Ranger(object):








        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getMaxAddress(self, __a0: object) -> ghidra.program.model.address.Address: ...

        def getMinAddress(self, __a0: object) -> ghidra.program.model.address.Address: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class CodeUnitRanger(object, ghidra.trace.util.OverlappingObjectIterator.Ranger):




        def __init__(self): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def getMaxAddress(self, __a0: ghidra.program.model.listing.CodeUnit) -> ghidra.program.model.address.Address: ...

        @overload
        def getMaxAddress(self, __a0: object) -> ghidra.program.model.address.Address: ...

        @overload
        def getMinAddress(self, __a0: ghidra.program.model.listing.CodeUnit) -> ghidra.program.model.address.Address: ...

        @overload
        def getMinAddress(self, __a0: object) -> ghidra.program.model.address.Address: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class SnapRangeKeyRanger(object, ghidra.trace.util.OverlappingObjectIterator.Ranger):




        def __init__(self): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def getMaxAddress(self, __a0: java.util.Map.Entry) -> ghidra.program.model.address.Address: ...

        @overload
        def getMaxAddress(self, __a0: object) -> ghidra.program.model.address.Address: ...

        @overload
        def getMinAddress(self, __a0: java.util.Map.Entry) -> ghidra.program.model.address.Address: ...

        @overload
        def getMinAddress(self, __a0: object) -> ghidra.program.model.address.Address: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class AddressRangeRanger(object, ghidra.trace.util.OverlappingObjectIterator.Ranger):




        def __init__(self): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        @overload
        def getMaxAddress(self, __a0: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.Address: ...

        @overload
        def getMaxAddress(self, __a0: object) -> ghidra.program.model.address.Address: ...

        @overload
        def getMinAddress(self, __a0: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.Address: ...

        @overload
        def getMinAddress(self, __a0: object) -> ghidra.program.model.address.Address: ...

        def hashCode(self) -> int: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...



    def __init__(self, __a0: java.util.Iterator, __a1: ghidra.trace.util.OverlappingObjectIterator.Ranger, __a2: java.util.Iterator, __a3: ghidra.trace.util.OverlappingObjectIterator.Ranger): ...

    def __iter__(self) -> Iterator[object]: ...

    def equals(self, __a0: object) -> bool: ...

    def forEachRemaining(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hasNext(self) -> bool: ...

    def hashCode(self) -> int: ...

    def next(self) -> object: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def peek(self) -> object: ...

    def remove(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

