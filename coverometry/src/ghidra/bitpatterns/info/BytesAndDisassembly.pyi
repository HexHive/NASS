import java.lang


class BytesAndDisassembly(object):




    def __init__(self, __a0: unicode, __a1: unicode): ...



    def equals(self, __a0: object) -> bool: ...

    def getBytes(self) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    def getDisassembly(self) -> unicode: ...

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
    def bytes(self) -> unicode: ...

    @property
    def disassembly(self) -> unicode: ...