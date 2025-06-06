import docking
import docking.action
import ghidra.app.cmd.memory
import ghidra.util
import ghidra.util.task
import java.awt
import java.awt.event
import java.lang
import java.util
import javax.swing


class MoveBlockDialog(docking.DialogComponentProvider, ghidra.app.cmd.memory.MoveBlockListener):








    def addAction(self, __a0: docking.action.DockingActionIf) -> None: ...

    def clearStatusText(self) -> None: ...

    def close(self) -> None: ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getActionContext(self, __a0: java.awt.event.MouseEvent) -> docking.ActionContext: ...

    def getActions(self) -> java.util.Set: ...

    def getBackground(self) -> java.awt.Color: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self) -> javax.swing.JComponent: ...

    def getDefaultButton(self) -> javax.swing.JButton: ...

    def getDefaultSize(self) -> java.awt.Dimension: ...

    def getFocusComponent(self) -> java.awt.Component: ...

    def getHelpLocation(self) -> ghidra.util.HelpLocation: ...

    def getId(self) -> int: ...

    def getInitialLocation(self) -> java.awt.Point: ...

    def getPreferredSize(self) -> java.awt.Dimension: ...

    def getRememberLocation(self) -> bool: ...

    def getRememberSize(self) -> bool: ...

    def getStatusText(self) -> unicode: ...

    def getTitle(self) -> unicode: ...

    def getUseSharedLocation(self) -> bool: ...

    def hashCode(self) -> int: ...

    def hideTaskMonitorComponent(self) -> None: ...

    def isModal(self) -> bool: ...

    def isResizeable(self) -> bool: ...

    def isRunningTask(self) -> bool: ...

    def isShowing(self) -> bool: ...

    def isTransient(self) -> bool: ...

    def isVisible(self) -> bool: ...

    def moveBlockCompleted(self, __a0: ghidra.app.cmd.memory.MoveBlockTask) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeAction(self, __a0: docking.action.DockingActionIf) -> None: ...

    def setBackground(self, __a0: java.awt.Color) -> None: ...

    def setCursor(self, __a0: java.awt.Cursor) -> None: ...

    def setDefaultButton(self, __a0: javax.swing.JButton) -> None: ...

    def setDefaultSize(self, __a0: int, __a1: int) -> None: ...

    def setFocusComponent(self, __a0: java.awt.Component) -> None: ...

    def setHelpLocation(self, __a0: ghidra.util.HelpLocation) -> None: ...

    def setInitialLocation(self, __a0: int, __a1: int) -> None: ...

    @overload
    def setMinimumSize(self, __a0: java.awt.Dimension) -> None: ...

    @overload
    def setMinimumSize(self, __a0: int, __a1: int) -> None: ...

    def setPreferredSize(self, __a0: int, __a1: int) -> None: ...

    def setRememberLocation(self, __a0: bool) -> None: ...

    def setRememberSize(self, __a0: bool) -> None: ...

    def setResizable(self, __a0: bool) -> None: ...

    def setStatusJustification(self, __a0: int) -> None: ...

    @overload
    def setStatusText(self, __a0: unicode) -> None: ...

    @overload
    def setStatusText(self, __a0: unicode, __a1: ghidra.util.MessageType) -> None: ...

    @overload
    def setStatusText(self, __a0: unicode, __a1: ghidra.util.MessageType, __a2: bool) -> None: ...

    def setTitle(self, __a0: unicode) -> None: ...

    def setTransient(self, __a0: bool) -> None: ...

    def setUseSharedLocation(self, __a0: bool) -> None: ...

    def showTaskMonitorComponent(self, __a0: unicode, __a1: bool, __a2: bool) -> ghidra.util.task.TaskMonitor: ...

    def stateChanged(self) -> None: ...

    def taskCancelled(self, __a0: ghidra.util.task.Task) -> None: ...

    def taskCompleted(self, __a0: ghidra.util.task.Task) -> None: ...

    def toFront(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def waitForCurrentTask(self) -> None: ...

