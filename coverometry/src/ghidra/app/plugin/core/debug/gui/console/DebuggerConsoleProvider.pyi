from typing import Iterator
from typing import List
import docking
import docking.action
import docking.actions
import ghidra.app.plugin.core.debug.gui.console
import ghidra.framework.plugintool
import ghidra.util
import java.awt.event
import java.lang
import java.util
import java.util.function
import java.util.stream
import javax.swing


class DebuggerConsoleProvider(ghidra.framework.plugintool.ComponentProviderAdapter, docking.actions.PopupActionProvider):





    class ActionList(java.util.ArrayList):




        def __init__(self): ...

        def __iter__(self): ...

        @overload
        def add(self, __a0: object) -> bool: ...

        @overload
        def add(self, __a0: int, __a1: object) -> None: ...

        @overload
        def addAll(self, __a0: java.util.Collection) -> bool: ...

        @overload
        def addAll(self, __a0: int, __a1: java.util.Collection) -> bool: ...

        def clear(self) -> None: ...

        def clone(self) -> object: ...

        def contains(self, __a0: object) -> bool: ...

        def containsAll(self, __a0: java.util.Collection) -> bool: ...

        @staticmethod
        def copyOf(__a0: java.util.Collection) -> List[object]: ...

        def ensureCapacity(self, __a0: int) -> None: ...

        def equals(self, __a0: object) -> bool: ...

        def forEach(self, __a0: java.util.function.Consumer) -> None: ...

        def get(self, __a0: int) -> object: ...

        def getClass(self) -> java.lang.Class: ...

        def hashCode(self) -> int: ...

        def indexOf(self, __a0: object) -> int: ...

        def isEmpty(self) -> bool: ...

        def iterator(self) -> java.util.Iterator: ...

        def lastIndexOf(self, __a0: object) -> int: ...

        @overload
        def listIterator(self) -> java.util.ListIterator: ...

        @overload
        def listIterator(self, __a0: int) -> java.util.ListIterator: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        @overload
        @staticmethod
        def of() -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: List[object]) -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: object) -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: object, __a1: object) -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: object, __a1: object, __a2: object) -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: object, __a1: object, __a2: object, __a3: object) -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object) -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object) -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object) -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object, __a7: object) -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object, __a7: object, __a8: object) -> List[object]: ...

        @overload
        @staticmethod
        def of(__a0: object, __a1: object, __a2: object, __a3: object, __a4: object, __a5: object, __a6: object, __a7: object, __a8: object, __a9: object) -> List[object]: ...

        def parallelStream(self) -> java.util.stream.Stream: ...

        def removeAll(self, __a0: java.util.Collection) -> bool: ...

        def removeIf(self, __a0: java.util.function.Predicate) -> bool: ...

        def replaceAll(self, __a0: java.util.function.UnaryOperator) -> None: ...

        def retainAll(self, __a0: java.util.Collection) -> bool: ...

        def set(self, __a0: int, __a1: object) -> object: ...

        def size(self) -> int: ...

        def spliterator(self) -> java.util.Spliterator: ...

        def stream(self) -> java.util.stream.Stream: ...

        def subList(self, __a0: int, __a1: int) -> List[object]: ...

        @overload
        def toArray(self) -> List[object]: ...

        @overload
        def toArray(self, __a0: List[object]) -> List[object]: ...

        @overload
        def toArray(self, __a0: java.util.function.IntFunction) -> List[object]: ...

        def toString(self) -> unicode: ...

        def trimToSize(self) -> None: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...






    class LogRow(object):




        def __init__(self, __a0: javax.swing.Icon, __a1: unicode, __a2: java.util.Date, __a3: docking.ActionContext, __a4: ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.ActionList): ...



        def equals(self, __a0: object) -> bool: ...

        def getActionContext(self) -> docking.ActionContext: ...

        def getActions(self) -> ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.ActionList: ...

        def getClass(self) -> java.lang.Class: ...

        def getDate(self) -> java.util.Date: ...

        def getIcon(self) -> javax.swing.Icon: ...

        def getMessage(self) -> unicode: ...

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
        def actionContext(self) -> docking.ActionContext: ...

        @property
        def actions(self) -> ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.ActionList: ...

        @property
        def date(self) -> java.util.Date: ...

        @property
        def icon(self) -> javax.swing.Icon: ...

        @property
        def message(self) -> unicode: ...




    class BoundAction(object):
        action: docking.action.DockingActionIf
        context: docking.ActionContext



        def __init__(self, __a0: docking.action.DockingActionIf, __a1: docking.ActionContext): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getIcon(self) -> javax.swing.Icon: ...

        def getName(self) -> unicode: ...

        def getTooltipText(self) -> unicode: ...

        def hashCode(self) -> int: ...

        def isEnabled(self) -> bool: ...

        def notify(self) -> None: ...

        def notifyAll(self) -> None: ...

        def perform(self) -> None: ...

        def toString(self) -> unicode: ...

        @overload
        def wait(self) -> None: ...

        @overload
        def wait(self, __a0: long) -> None: ...

        @overload
        def wait(self, __a0: long, __a1: int) -> None: ...

        @property
        def enabled(self) -> bool: ...

        @property
        def icon(self) -> javax.swing.Icon: ...

        @property
        def name(self) -> unicode: ...

        @property
        def tooltipText(self) -> unicode: ...

    def __init__(self, __a0: ghidra.app.plugin.core.debug.gui.console.DebuggerConsolePlugin): ...



    def addLocalAction(self, __a0: docking.action.DockingActionIf) -> None: ...

    def addToTool(self) -> None: ...

    def adjustFontSize(self, __a0: bool) -> None: ...

    def canBeParent(self) -> bool: ...

    def closeComponent(self) -> None: ...

    def componentActivated(self) -> None: ...

    def componentDeactived(self) -> None: ...

    def componentHidden(self) -> None: ...

    def componentShown(self) -> None: ...

    def contextChanged(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getActionContext(self, __a0: java.awt.event.MouseEvent) -> docking.ActionContext: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self) -> javax.swing.JComponent: ...

    def getContextType(self) -> java.lang.Class: ...

    def getDefaultWindowPosition(self) -> docking.WindowPosition: ...

    def getHelpInfo(self) -> unicode: ...

    def getHelpLocation(self) -> ghidra.util.HelpLocation: ...

    def getHelpObject(self) -> object: ...

    def getIcon(self) -> javax.swing.Icon: ...

    def getInstanceID(self) -> long: ...

    def getIntraGroupPosition(self) -> docking.WindowPosition: ...

    def getLogRow(self, __a0: docking.ActionContext) -> ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.LogRow: ...

    @staticmethod
    def getMappedName(__a0: unicode, __a1: unicode) -> unicode: ...

    @staticmethod
    def getMappedOwner(__a0: unicode, __a1: unicode) -> unicode: ...

    def getName(self) -> unicode: ...

    def getOwner(self) -> unicode: ...

    def getPopupActions(self, __a0: docking.Tool, __a1: docking.ActionContext) -> List[object]: ...

    def getSubTitle(self) -> unicode: ...

    def getTabText(self) -> unicode: ...

    def getTitle(self) -> unicode: ...

    def getTool(self) -> docking.Tool: ...

    def getWindowGroup(self) -> unicode: ...

    def getWindowSubMenuName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isActive(self) -> bool: ...

    def isFocusedProvider(self) -> bool: ...

    def isInTool(self) -> bool: ...

    def isSnapshot(self) -> bool: ...

    def isTransient(self) -> bool: ...

    def isVisible(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def registerProviderNameOwnerChange(__a0: unicode, __a1: unicode, __a2: unicode, __a3: unicode) -> None: ...

    def removeFromTool(self) -> None: ...

    def requestFocus(self) -> None: ...

    def resetFontSize(self) -> None: ...

    def setHelpLocation(self, __a0: ghidra.util.HelpLocation) -> None: ...

    def setIntraGroupPosition(self, __a0: docking.WindowPosition) -> None: ...

    def setSubTitle(self, __a0: unicode) -> None: ...

    def setTabText(self, __a0: unicode) -> None: ...

    def setTitle(self, __a0: unicode) -> None: ...

    def setVisible(self, __a0: bool) -> None: ...

    def toFront(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def component(self) -> javax.swing.JComponent: ...