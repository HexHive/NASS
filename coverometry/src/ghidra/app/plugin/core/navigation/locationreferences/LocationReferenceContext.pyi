from typing import List
import ghidra.app.plugin.core.navigation.locationreferences
import java.lang


class LocationReferenceContext(object):
    EMPTY_CONTEXT: ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext = 







    def equals(self, __a0: object) -> bool: ...

    @overload
    @staticmethod
    def get(__a0: unicode) -> ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext: ...

    @overload
    @staticmethod
    def get(__a0: ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext) -> ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext: ...

    def getBoldMatchingText(self) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    def getMatches(self) -> List[object]: ...

    def getPlainText(self) -> unicode: ...

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

    @property
    def boldMatchingText(self) -> unicode: ...

    @property
    def matches(self) -> List[object]: ...

    @property
    def plainText(self) -> unicode: ...