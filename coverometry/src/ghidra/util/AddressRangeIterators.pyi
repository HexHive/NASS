from typing import List
import ghidra.program.model.address
import ghidra.util
import java.lang
import java.util


class AddressRangeIterators(java.lang.Enum):








    @staticmethod
    def castOrWrap(__a0: java.util.Iterator) -> ghidra.program.model.address.AddressRangeIterator: ...

    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def intersect(__a0: java.util.Iterator, __a1: java.util.Iterator, __a2: bool) -> ghidra.program.model.address.AddressRangeIterator: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def subtract(__a0: java.util.Iterator, __a1: java.util.Iterator, __a2: ghidra.program.model.address.Address, __a3: bool) -> ghidra.program.model.address.AddressRangeIterator: ...

    def toString(self) -> unicode: ...

    @staticmethod
    def union(__a0: java.util.Collection, __a1: bool) -> ghidra.program.model.address.AddressRangeIterator: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.util.AddressRangeIterators: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.util.AddressRangeIterators]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @staticmethod
    def xor(__a0: java.util.Iterator, __a1: java.util.Iterator, __a2: ghidra.program.model.address.Address, __a3: bool) -> ghidra.program.model.address.AddressRangeIterator: ...

