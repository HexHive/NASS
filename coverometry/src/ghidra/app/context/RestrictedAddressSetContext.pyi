import java.lang


class RestrictedAddressSetContext(object):
    """
    Marker interface for Navigatable contexts that don't support navigating to the entire
     program. Typically, these are used by providers that show only one function at a time such
     as the Decompiler.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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

