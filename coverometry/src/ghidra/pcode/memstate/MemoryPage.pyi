from typing import List
import java.lang


class MemoryPage(object):
    data: List[int]



    @overload
    def __init__(self, __a0: int): ...

    @overload
    def __init__(self, __a0: List[int]): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getInitializedByteCount(self, __a0: int, __a1: int) -> int: ...

    @overload
    @staticmethod
    def getInitializedByteCount(__a0: List[int], __a1: int, __a2: int) -> int: ...

    @overload
    def getInitializedMask(self) -> List[int]: ...

    @overload
    @staticmethod
    def getInitializedMask(__a0: int, __a1: bool) -> List[int]: ...

    @overload
    @staticmethod
    def getInitializedMask(__a0: int, __a1: int, __a2: int, __a3: bool) -> List[int]: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def setInitialized(self) -> None: ...

    @overload
    def setInitialized(self, __a0: int, __a1: int) -> None: ...

    @overload
    def setInitialized(self, __a0: int, __a1: int, __a2: List[int]) -> None: ...

    @overload
    @staticmethod
    def setInitialized(__a0: List[int], __a1: int, __a2: int) -> None: ...

    @overload
    def setUninitialized(self) -> None: ...

    @overload
    def setUninitialized(self, __a0: int, __a1: int) -> None: ...

    @overload
    @staticmethod
    def setUninitialized(__a0: List[int], __a1: int, __a2: int) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def initializedMask(self) -> List[int]: ...