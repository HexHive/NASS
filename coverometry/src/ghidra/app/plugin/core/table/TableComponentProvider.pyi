import docking
import docking.action
import docking.widgets.table.threaded
import ghidra.app.nav
import ghidra.framework.plugintool
import ghidra.util
import ghidra.util.table
import java.awt.event
import java.lang
import javax.swing
import javax.swing.event


class TableComponentProvider(ghidra.framework.plugintool.ComponentProviderAdapter, javax.swing.event.TableModelListener, ghidra.app.nav.NavigatableRemovalListener):








    def addActivationListener(self, __a0: docking.ComponentProviderActivationListener) -> None: ...

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

    def getActionOwner(self) -> unicode: ...

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

    @staticmethod
    def getMappedName(__a0: unicode, __a1: unicode) -> unicode: ...

    @staticmethod
    def getMappedOwner(__a0: unicode, __a1: unicode) -> unicode: ...

    def getModel(self) -> ghidra.util.table.GhidraProgramTableModel: ...

    def getName(self) -> unicode: ...

    def getOwner(self) -> unicode: ...

    def getSubTitle(self) -> unicode: ...

    def getTabText(self) -> unicode: ...

    def getThreadedTablePanel(self) -> docking.widgets.table.threaded.GThreadedTablePanel: ...

    def getTitle(self) -> unicode: ...

    def getTool(self) -> docking.Tool: ...

    def getWindowGroup(self) -> unicode: ...

    def getWindowSubMenuName(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def installRemoveItemsAction(self) -> None: ...

    def isActive(self) -> bool: ...

    def isFocusedProvider(self) -> bool: ...

    def isInTool(self) -> bool: ...

    def isSnapshot(self) -> bool: ...

    def isTransient(self) -> bool: ...

    def isVisible(self) -> bool: ...

    def navigatableRemoved(self, __a0: ghidra.app.nav.Navigatable) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def refresh(self) -> None: ...

    @staticmethod
    def registerProviderNameOwnerChange(__a0: unicode, __a1: unicode, __a2: unicode, __a3: unicode) -> None: ...

    def removeActivationListener(self, __a0: docking.ComponentProviderActivationListener) -> None: ...

    def removeFromTool(self) -> None: ...

    def requestFocus(self) -> None: ...

    def resetFontSize(self) -> None: ...

    def setHelpLocation(self, __a0: ghidra.util.HelpLocation) -> None: ...

    def setIntraGroupPosition(self, __a0: docking.WindowPosition) -> None: ...

    def setSubTitle(self, __a0: unicode) -> None: ...

    def setTabText(self, __a0: unicode) -> None: ...

    def setTitle(self, __a0: unicode) -> None: ...

    def setVisible(self, __a0: bool) -> None: ...

    def tableChanged(self, __a0: javax.swing.event.TableModelEvent) -> None: ...

    def toFront(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def actionOwner(self) -> unicode: ...

    @property
    def component(self) -> javax.swing.JComponent: ...

    @property
    def model(self) -> ghidra.util.table.GhidraProgramTableModel: ...

    @property
    def threadedTablePanel(self) -> docking.widgets.table.threaded.GThreadedTablePanel: ...

    @property
    def windowSubMenuName(self) -> unicode: ...