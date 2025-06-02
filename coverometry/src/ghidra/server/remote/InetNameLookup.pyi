import java.lang


class InetNameLookup(object):








    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def getCanonicalHostName(__a0: unicode) -> unicode: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def isEnabled() -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def setDisableOnFailure(__a0: bool) -> None: ...

    @staticmethod
    def setLookupEnabled(__a0: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

