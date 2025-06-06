from typing import List
import java.io
import java.lang


class DBBufferOutputStream(java.io.OutputStream):




    @overload
    def __init__(self, __a0: db.DBBuffer): ...

    @overload
    def __init__(self, __a0: db.DBBuffer, __a1: int): ...



    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def flush(self) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def nullOutputStream() -> java.io.OutputStream: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @overload
    def write(self, __a0: int) -> None: ...

    @overload
    def write(self, __a0: List[int]) -> None: ...

    @overload
    def write(self, __a0: List[int], __a1: int, __a2: int) -> None: ...

