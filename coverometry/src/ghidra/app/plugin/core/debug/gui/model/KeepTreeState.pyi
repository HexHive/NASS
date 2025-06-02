import docking.widgets.tree
import ghidra.app.plugin.core.debug.gui.model
import java.lang


class KeepTreeState(object, java.lang.AutoCloseable):




    def __init__(self, __a0: docking.widgets.tree.GTree): ...



    def close(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def ifNotNull(__a0: docking.widgets.tree.GTree) -> ghidra.app.plugin.core.debug.gui.model.KeepTreeState: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

