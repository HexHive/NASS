from typing import Iterator
from typing import List
import java.lang
import java.util
import java.util.function


class LoaderMap(java.util.TreeMap):
    """
    A Map of Loaders to their respective LoadSpecs.
 
     The Loader keys are sorted according to their Loader#compareTo(Loader).
    """





    def __init__(self): ...

    def __iter__(self): ...

    def ceilingEntry(self, __a0: object) -> java.util.Map.Entry: ...

    def ceilingKey(self, __a0: object) -> object: ...

    def clear(self) -> None: ...

    def clone(self) -> object: ...

    def comparator(self) -> java.util.Comparator: ...

    def compute(self, __a0: object, __a1: java.util.function.BiFunction) -> object: ...

    def computeIfAbsent(self, __a0: object, __a1: java.util.function.Function) -> object: ...

    def computeIfPresent(self, __a0: object, __a1: java.util.function.BiFunction) -> object: ...

    def containsKey(self, __a0: object) -> bool: ...

    def containsValue(self, __a0: object) -> bool: ...

    @staticmethod
    def copyOf(__a0: java.util.Map) -> java.util.Map: ...

    def descendingKeySet(self) -> java.util.NavigableSet: ...

    def descendingMap(self) -> java.util.NavigableMap: ...

    @staticmethod
    def entry(__a0: object, __a1: object) -> java.util.Map.Entry: ...

    def entrySet(self) -> java.util.Set: ...

    def equals(self, __a0: object) -> bool: ...

    def firstEntry(self) -> java.util.Map.Entry: ...

    def firstKey(self) -> object: ...

    def floorEntry(self, __a0: object) -> java.util.Map.Entry: ...

    def floorKey(self, __a0: object) -> object: ...

    def forEach(self, __a0: java.util.function.BiConsumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def getOrDefault(self, __a0: object, __a1: object) -> object: ...

    def hashCode(self) -> int: ...

    @overload
    def headMap(self, __a0: object) -> java.util.SortedMap: ...

    @overload
    def headMap(self, __a0: object, __a1: bool) -> java.util.NavigableMap: ...

    def higherEntry(self, __a0: object) -> java.util.Map.Entry: ...

    def higherKey(self, __a0: object) -> object: ...

    def isEmpty(self) -> bool: ...

    def keySet(self) -> java.util.Set: ...

    def lastEntry(self) -> java.util.Map.Entry: ...

    def lastKey(self) -> object: ...

    def lowerEntry(self, __a0: object) -> java.util.Map.Entry: ...

    def lowerKey(self, __a0: object) -> object: ...

    def merge(self, __a0: object, __a1: object, __a2: java.util.function.BiFunction) -> object: ...

    def navigableKeySet(self) -> java.util.NavigableSet: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    @staticmethod
    def of() -> java.util.Map: ...

    @overload
    @staticmethod
    def of(__a0: object, __a1: object) -> java.util.Map: ...

    @overload
    @staticmethod
    def of(__a0: object, __a1: object, __a2: object, __a3: object) -> java.util.Map: ...

    @overload
    @staticmethod
    def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object) -> java.util.Map: ...

    @overload
    @staticmethod
    def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object, __a7: object) -> java.util.Map: ...

    @overload
    @staticmethod
    def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object, __a7: object, __a8: object, __a9: object) -> java.util.Map: ...

    @overload
    @staticmethod
    def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object, __a7: object, __a8: object, __a9: object, __a10: object, __a11: object) -> java.util.Map: ...

    @overload
    @staticmethod
    def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object, __a7: object, __a8: object, __a9: object, __a10: object, __a11: object, __a12: object, __a13: object) -> java.util.Map: ...

    @overload
    @staticmethod
    def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object, __a7: object, __a8: object, __a9: object, __a10: object, __a11: object, __a12: object, __a13: object, __a14: object, __a15: object) -> java.util.Map: ...

    @overload
    @staticmethod
    def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object, __a7: object, __a8: object, __a9: object, __a10: object, __a11: object, __a12: object, __a13: object, __a14: object, __a15: object, __a16: object, __a17: object) -> java.util.Map: ...

    @overload
    @staticmethod
    def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object, __a7: object, __a8: object, __a9: object, __a10: object, __a11: object, __a12: object, __a13: object, __a14: object, __a15: object, __a16: object, __a17: object, __a18: object, __a19: object) -> java.util.Map: ...

    @staticmethod
    def ofEntries(__a0: List[java.util.Map.Entry]) -> java.util.Map: ...

    def pollFirstEntry(self) -> java.util.Map.Entry: ...

    def pollLastEntry(self) -> java.util.Map.Entry: ...

    def put(self, __a0: object, __a1: object) -> object: ...

    def putAll(self, __a0: java.util.Map) -> None: ...

    def putIfAbsent(self, __a0: object, __a1: object) -> object: ...

    @overload
    def remove(self, __a0: object) -> object: ...

    @overload
    def remove(self, __a0: object, __a1: object) -> bool: ...

    @overload
    def replace(self, __a0: object, __a1: object) -> object: ...

    @overload
    def replace(self, __a0: object, __a1: object, __a2: object) -> bool: ...

    def replaceAll(self, __a0: java.util.function.BiFunction) -> None: ...

    def size(self) -> int: ...

    @overload
    def subMap(self, __a0: object, __a1: object) -> java.util.SortedMap: ...

    @overload
    def subMap(self, __a0: object, __a1: bool, __a2: object, __a3: bool) -> java.util.NavigableMap: ...

    @overload
    def tailMap(self, __a0: object) -> java.util.SortedMap: ...

    @overload
    def tailMap(self, __a0: object, __a1: bool) -> java.util.NavigableMap: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

