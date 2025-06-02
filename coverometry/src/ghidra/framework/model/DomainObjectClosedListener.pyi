import ghidra.framework.model
import java.lang


class DomainObjectClosedListener(object):
    """
    An interface that allows for a callback when a DomainObject is closed.
    """









    def domainObjectClosed(self, dobj: ghidra.framework.model.DomainObject) -> None:
        """
        Callback indicating that the specified {@link DomainObject} has been closed.
        @param dobj domain object
        """
        ...

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

