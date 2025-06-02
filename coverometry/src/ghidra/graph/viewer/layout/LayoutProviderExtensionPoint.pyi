import ghidra.graph
import ghidra.graph.viewer.layout
import ghidra.util.classfinder
import ghidra.util.task
import java.lang
import javax.swing


class LayoutProviderExtensionPoint(ghidra.graph.viewer.layout.LayoutProvider, ghidra.util.classfinder.ExtensionPoint, object):
    """
    A version of LayoutProvider that is discoverable at runtime.   Layouts that do not wish 
     to be discoverable should implement LayoutProvider directly, not this interface.
    """









    def equals(self, __a0: object) -> bool: ...

    def getActionIcon(self) -> javax.swing.Icon: ...

    def getClass(self) -> java.lang.Class: ...

    def getLayout(self, __a0: ghidra.graph.VisualGraph, __a1: ghidra.util.task.TaskMonitor) -> ghidra.graph.viewer.layout.VisualGraphLayout: ...

    def getLayoutName(self) -> unicode: ...

    def getPriorityLevel(self) -> int: ...

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
    def actionIcon(self) -> javax.swing.Icon: ...

    @property
    def layoutName(self) -> unicode: ...

    @property
    def priorityLevel(self) -> int: ...