from typing import List
import java.lang
import java.util


class RegisterState(object):








    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getKeys(self) -> java.util.Set: ...

    def getVals(self, __a0: unicode) -> List[object]: ...

    def hashCode(self) -> int: ...

    def isInitialized(self, __a0: unicode) -> List[object]: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def setVals(self, __a0: unicode, __a1: List[int], __a2: bool) -> None: ...

    @overload
    def setVals(self, __a0: unicode, __a1: long, __a2: int, __a3: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def keys(self) -> java.util.Set: ...