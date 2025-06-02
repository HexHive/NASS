from typing import List
import docking
import ghidra.app.util
import ghidra.util.task
import java.awt.datatransfer
import java.lang
import javax.swing.event


class ClipboardContentProviderService(object):
    """
    Determines what types of transfer data can be placed on the clipboard, as well as if 
     cut, copy, and paste operations are supported
    """









    def addChangeListener(self, listener: javax.swing.event.ChangeListener) -> None:
        """
        Adds a change listener that will be notified when the state of the service provider changes
         such that the ability to perform some actions has changed.  For example, the given
         listener will be called when a copy action can be performed when it was previously not
         possible.
        @param listener The listener to add.
        """
        ...

    def canCopy(self) -> bool:
        """
        Returns true if the given service provider can currently perform a copy operation.
        @return true if the given service provider can currently perform a copy operation.
        """
        ...

    def canCopySpecial(self) -> bool:
        """
        Returns true if the given service provider can currently perform a 'copy special' 
         operation.
        @return true if copy special is enabled
        """
        ...

    def canPaste(self, availableFlavors: List[java.awt.datatransfer.DataFlavor]) -> bool:
        """
        Returns true if the service can perform a paste operation using the given transferable.
        @param availableFlavors data flavors available for the current clipboard transferable
        @return true if the service can perform a paste operation using the given transferable.
        """
        ...

    def copy(self, monitor: ghidra.util.task.TaskMonitor) -> java.awt.datatransfer.Transferable:
        """
        Triggers the default copy operation
        @param monitor monitor that shows progress of the copy to clipboard, and
         may be canceled
        @return the created transferable; null if the copy was unsuccessful
        """
        ...

    def copySpecial(self, copyType: ghidra.app.util.ClipboardType, monitor: ghidra.util.task.TaskMonitor) -> java.awt.datatransfer.Transferable:
        """
        Triggers a special copy with the specified copy type.
        @param copyType contains the data flavor of the clipboard contents
        @param monitor monitor that shows progress of the copy to clipboard, and
         may be canceled
        @return the created transferable; null if the copy was unsuccessful
        """
        ...

    def enableCopy(self) -> bool:
        """
        Returns true if copy should be enabled; false if it should be disabled.  This method can
         be used in conjunction with {@link #copy(TaskMonitor)} in order to add menu items to
         popup menus but to have them enabled when appropriate.
        @return true if copy should be enabled
        """
        ...

    def enableCopySpecial(self) -> bool:
        """
        Returns true if copySpecial actions should be enabled;
        @return true if copySpecial actions should be enabled;
        """
        ...

    def enablePaste(self) -> bool:
        """
        Returns true if paste should be enabled; false if it should be disabled.  This method can
         be used in conjunction with {@link #paste(Transferable)} in order to add menu items to
         popup menus but to have them enabled when appropriate.
        @return true if paste should be enabled
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponentProvider(self) -> docking.ComponentProvider:
        """
        Returns the component provider associated with this service
        @return the provider
        """
        ...

    def getCurrentCopyTypes(self) -> List[ghidra.app.util.ClipboardType]:
        """
        Gets the currently active ClipboardTypes for copying with the current context
        @return the types
        """
        ...

    def hashCode(self) -> int: ...

    def isValidContext(self, context: docking.ActionContext) -> bool:
        """
        Return whether the given context is valid for actions on popup menus.
        @param context the context of where the popup menu will be positioned.
        @return true if valid
        """
        ...

    def lostOwnership(self, transferable: java.awt.datatransfer.Transferable) -> None:
        """
        Notification that the clipboard owner has lost its ownership.
        @param transferable the contents which the owner had placed on the clipboard
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def paste(self, pasteData: java.awt.datatransfer.Transferable) -> bool:
        """
        Triggers the default paste operation for the given transferable
        @param pasteData the paste transferable
        @return true of the paste was successful
        """
        ...

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener) -> None:
        """
        Removes the given change listener.
        @param listener The listener to remove.
        @see #addChangeListener(ChangeListener)
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def componentProvider(self) -> docking.ComponentProvider: ...

    @property
    def currentCopyTypes(self) -> List[object]: ...