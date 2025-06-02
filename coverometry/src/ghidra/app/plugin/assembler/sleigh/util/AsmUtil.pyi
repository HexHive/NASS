from typing import List
import java.lang
import java.util


class AsmUtil(object):
    """
    Utilities for the Assembler
    """





    def __init__(self): ...



    @staticmethod
    def compareArrays(a: List[int], b: List[int]) -> int:
        """
        Compare two byte arrays by their corresponding entries
 
         <p>
         If the two arrays have differing lengths, the shorter precedes the longer. Otherwise, they
         are compared as in C's {@code memcmp}, except that Java {@code byte}s are signed.
        @param a the first array
        @param b the second array
        @return a comparison result as in {@link Comparable#compareTo(Object)}
        """
        ...

    @staticmethod
    def compareInOrder(a: java.util.Collection, b: java.util.Collection) -> int:
        """
        Compare two collections by their corresponding elements in order
 
         <p>
         If the collections have differing sizes, the ordering does not matter. The smaller collection
         precedes the larger. Otherwise, each corresponding pair of elements are compared. Once an
         unequal pair is found, the collections are ordered by those elements. This is analogous to
         {@link String} comparison.
        @param a the first set
        @param b the second set
        @return a comparison result as in {@link Comparable#compareTo(Object)}
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def extendList(list: List[object], ext: object) -> List[object]:
        """
        Extend a list with the given item
 
         <p>
         Used in functional style when the list is immutable.
        @param <T> the type of elements
        @param list the list
        @param ext the additional item
        @return an immutable copy of the list with the given item appended
        """
        ...

    def getClass(self) -> java.lang.Class: ...

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

