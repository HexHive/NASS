import java.lang


class GFileSystemProbe(object):
    """
    An empty interface that is a common type for the real probe interfaces to derive from.
 
     See GFileSystemProbeBytesOnly, GFileSystemProbeByteProvider
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

