import ghidra.app.plugin.core.debug.gui.objects
import java.lang


class ObjectUpdateService(object):








    def equals(self, __a0: object) -> bool: ...

    def fireObjectUpdated(self, __a0: ghidra.app.plugin.core.debug.gui.objects.ObjectContainer) -> None: ...

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

