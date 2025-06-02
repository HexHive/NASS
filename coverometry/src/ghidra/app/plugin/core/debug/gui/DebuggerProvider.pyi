import docking
import docking.action
import java.awt.event
import java.lang


class DebuggerProvider(object):








    def addLocalAction(self, __a0: docking.action.DockingActionIf) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getActionContext(self, __a0: java.awt.event.MouseEvent) -> docking.ActionContext: ...

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

