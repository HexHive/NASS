import java.lang


class HexLong(java.lang.Number):




    def __init__(self, longValue: long): ...



    def byteValue(self) -> int: ...

    def doubleValue(self) -> float: ...

    def equals(self, __a0: object) -> bool: ...

    def floatValue(self) -> float: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def intValue(self) -> int: ...

    def longValue(self) -> long: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def shortValue(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

