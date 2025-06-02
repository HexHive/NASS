import ghidra.util.database.spatial
import java.lang


class BoundedShape(object):








    def description(self) -> unicode: ...

    def equals(self, __a0: object) -> bool: ...

    def getBounds(self) -> ghidra.util.database.spatial.BoundingShape: ...

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

    @property
    def bounds(self) -> ghidra.util.database.spatial.BoundingShape: ...