import java.lang


class CryptoKeyFileTemplateWriter(object):




    def __init__(self, __a0: unicode): ...



    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def exists(self) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def open(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def write(self, __a0: unicode) -> None: ...

