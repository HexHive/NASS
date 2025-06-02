import docking.widgets.table
import ghidra.app.plugin.core.debug.gui.register
import java.lang


class TaintDebuggerRegisterColumnFactory(object, ghidra.app.plugin.core.debug.gui.register.DebuggerRegisterColumnFactory):
    COL_NAME: unicode = u'Taint'



    def __init__(self): ...



    def create(self) -> docking.widgets.table.DynamicTableColumn: ...

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

