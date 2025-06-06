from typing import List
import ghidra.dbg.target
import ghidra.dbg.util
import java.lang
import java.util
import java.util.concurrent


class PathMatcher(object, ghidra.dbg.util.PathPredicates):
    EMPTY: ghidra.dbg.util.PathPredicates = ghidra.dbg.util.PathPredicates$1@88ec1a7



    def __init__(self): ...



    def addAll(self, __a0: ghidra.dbg.util.PathMatcher) -> None: ...

    @overload
    def addPattern(self, __a0: ghidra.dbg.util.PathPattern) -> None: ...

    @overload
    def addPattern(self, __a0: List[object]) -> None: ...

    def ancestorCouldMatchRight(self, __a0: List[object], __a1: bool) -> bool: ...

    def ancestorMatches(self, __a0: List[object], __a1: bool) -> bool: ...

    @staticmethod
    def anyMatches(__a0: java.util.Set, __a1: unicode) -> bool: ...

    @overload
    def applyIntKeys(self, __a0: List[int]) -> ghidra.dbg.util.PathPredicates: ...

    @overload
    def applyIntKeys(self, __a0: int, __a1: ghidra.dbg.util.PathPredicates.Align, __a2: List[int]) -> ghidra.dbg.util.PathPredicates: ...

    @overload
    def applyIntKeys(self, __a0: int, __a1: ghidra.dbg.util.PathPredicates.Align, __a2: List[object]) -> ghidra.dbg.util.PathPredicates: ...

    @overload
    def applyKeys(self, __a0: List[unicode]) -> ghidra.dbg.util.PathPredicates: ...

    @overload
    def applyKeys(self, __a0: ghidra.dbg.util.PathPredicates.Align, __a1: List[unicode]) -> ghidra.dbg.util.PathPredicates: ...

    @overload
    def applyKeys(self, __a0: ghidra.dbg.util.PathPredicates.Align, __a1: List[object]) -> ghidra.dbg.util.PathPredicates: ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def fetchSuccessors(self, __a0: ghidra.dbg.target.TargetObject) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def fetchSuccessors(self, __a0: java.util.Map, __a1: List[object], __a2: ghidra.dbg.target.TargetObject) -> java.util.concurrent.CompletableFuture: ...

    @overload
    def getCachedSuccessors(self, __a0: ghidra.dbg.target.TargetObject) -> java.util.NavigableMap: ...

    @overload
    def getCachedSuccessors(self, __a0: java.util.Map, __a1: List[object], __a2: ghidra.dbg.target.TargetObject) -> None: ...

    @overload
    def getCachedValues(self, __a0: ghidra.dbg.target.TargetObject) -> java.util.NavigableMap: ...

    @overload
    def getCachedValues(self, __a0: List[object], __a1: object) -> java.util.NavigableMap: ...

    @overload
    def getCachedValues(self, __a0: java.util.Map, __a1: List[object], __a2: object) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def getNextIndices(self, __a0: List[object]) -> java.util.Set: ...

    def getNextKeys(self, __a0: List[object]) -> java.util.Set: ...

    def getNextNames(self, __a0: List[object]) -> java.util.Set: ...

    def getPatterns(self) -> java.util.Collection: ...

    def getPrevKeys(self, __a0: List[object]) -> java.util.Set: ...

    def getSingletonPath(self) -> List[object]: ...

    def getSingletonPattern(self) -> ghidra.dbg.util.PathPattern: ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    @staticmethod
    def keyMatches(__a0: unicode, __a1: unicode) -> bool: ...

    def matches(self, __a0: List[object]) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def or(self, __a0: ghidra.dbg.util.PathPredicates) -> ghidra.dbg.util.PathPredicates: ...

    @staticmethod
    def parse(__a0: unicode) -> ghidra.dbg.util.PathPredicates: ...

    @overload
    @staticmethod
    def pattern(__a0: List[unicode]) -> ghidra.dbg.util.PathPredicates: ...

    @overload
    @staticmethod
    def pattern(__a0: List[object]) -> ghidra.dbg.util.PathPredicates: ...

    def removeRight(self, __a0: int) -> ghidra.dbg.util.PathPredicates: ...

    def successorCouldMatch(self, __a0: List[object], __a1: bool) -> bool: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def empty(self) -> bool: ...

    @property
    def patterns(self) -> java.util.Collection: ...

    @property
    def singletonPath(self) -> List[object]: ...

    @property
    def singletonPattern(self) -> ghidra.dbg.util.PathPattern: ...