from typing import List
import java.lang


class FrequentSequence(object):




    def __init__(self, __a0: List[object], __a1: int): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getSequence(self) -> List[object]: ...

    def getSupport(self) -> int: ...

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
    def sequence(self) -> List[object]: ...

    @property
    def support(self) -> int: ...