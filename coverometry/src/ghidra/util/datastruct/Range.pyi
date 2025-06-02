from typing import Iterator
import ghidra.util.datastruct
import java.lang
import java.util
import java.util.function


class Range(object, java.lang.Comparable, java.lang.Iterable):
    """
    A class for holding a minimum and maximum signed int values that define a range.
    """

    max: int
    min: int



    def __init__(self, min: int, max: int):
        """
        Creates a range whose extent is from min to max.
        @param min the minimum extent.
        @param max the maximum extent (inclusive).
        @throws IllegalArgumentException if max is less than min.
        """
        ...

    def __iter__(self): ...

    @overload
    def compareTo(self, other: ghidra.util.datastruct.Range) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def contains(self, value: int) -> bool:
        """
        Returns true if the value is within the ranges extent.
        @param value the value to check.
        @return true if the value is within the ranges extent.
        """
        ...

    def equals(self, obj: object) -> bool: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def iterator(self) -> Iterator[int]: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def size(self) -> long:
        """
        Returns the range's size.
        @return the size
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

