import docking.widgets
import ghidra.program.util
import java.lang


class ProgramSelectionListener(object):
    """
    Listener that is notified when the program selection changes
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def programSelectionChanged(self, selection: ghidra.program.util.ProgramSelection, trigger: docking.widgets.EventTrigger) -> None:
        """
        Called whenever the program selection changes.
        @param selection the new program selection.
        @param trigger the cause of the change
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

