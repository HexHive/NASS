from typing import List
import java.io
import java.lang


class ObfuscatedOutputStream(java.io.OutputStream):
    """
    An OutputStream wrapper that obfuscates the bytes being written to the underlying
     stream.
    """





    def __init__(self, delegate: java.io.OutputStream):
        """
        Creates instance.
        @param delegate {@link OutputStream} to wrap
        """
        ...



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
    def write(self, b: int) -> None: ...

    @overload
    def write(self, __a0: List[int]) -> None: ...

    @overload
    def write(self, b: List[int], off: int, len: int) -> None: ...

