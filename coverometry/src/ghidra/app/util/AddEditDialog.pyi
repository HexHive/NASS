import docking
import docking.action
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util
import ghidra.util.task
import java.awt
import java.awt.event
import java.lang
import java.util
import javax.swing


class AddEditDialog(docking.DialogComponentProvider):
    """
    Dialog used to a label or to edit an existing label.
    """






    class NamespaceWrapper(object):




        def __init__(self, __a0: ghidra.app.util.AddEditDialog, __a1: ghidra.program.model.symbol.Namespace): ...



        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getNamespace(self) -> ghidra.program.model.symbol.Namespace: ...

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
        def namespace(self) -> ghidra.program.model.symbol.Namespace: ...

    def __init__(self, title: unicode, tool: ghidra.framework.plugintool.PluginTool): ...



    def addAction(self, action: docking.action.DockingActionIf) -> None:
        """
        Add an action to this dialog.  Only actions with icons are added to the toolbar.
         Note, if you add an action to this dialog, do not also add the action to
         the tool, as this dialog will do that for you.
        @param action the action
        """
        ...

    @overload
    def addLabel(self, address: ghidra.program.model.address.Address, prog: ghidra.program.model.listing.Program) -> None:
        """
        Invokes the dialog to add a new label in the given program at the given address
        @param address the address at which to add a new label
        @param prog the program in which to add a new label
        """
        ...

    @overload
    def addLabel(self, address: ghidra.program.model.address.Address, targetProgram: ghidra.program.model.listing.Program, provider: docking.ComponentProvider) -> None:
        """
        Invokes the dialog to add a new label in the given program at the given address
        @param address the address at which to add a new label
        @param targetProgram the program in which to add a new label
        @param provider the ComponentProvider to parent and center the dialog over.
        """
        ...

    @overload
    def addLabel(self, address: ghidra.program.model.address.Address, targetProgram: ghidra.program.model.listing.Program, centeredOverComponent: java.awt.Component) -> None:
        """
        Invokes the dialog to add a new label in the given program at the given address
        @param address the address at which to add a new label
        @param targetProgram the program in which to add a new label
        @param centeredOverComponent the component over which to center the dialog
        """
        ...

    def clearStatusText(self) -> None:
        """
        Clears the text from the dialog's status line.
        """
        ...

    def close(self) -> None: ...

    def dispose(self) -> None:
        """
        Disposes this dialog.  Only call this when the dialog is no longer used.  Calling this method
         will close the dialog if it is open.
        """
        ...

    @overload
    def editLabel(self, targetSymbol: ghidra.program.model.symbol.Symbol, targetProgram: ghidra.program.model.listing.Program) -> None:
        """
        Invokes the dialog to edit an existing label in the given program
        @param targetSymbol the symbol(label) to edit
        @param targetProgram the program containing the symbol
        """
        ...

    @overload
    def editLabel(self, targetSymbol: ghidra.program.model.symbol.Symbol, targetProgram: ghidra.program.model.listing.Program, provider: docking.ComponentProvider) -> None:
        """
        Invokes the dialog to edit an existing label in the given program
        @param targetSymbol the symbol(label) to edit
        @param targetProgram the program containing the symbol
        @param provider the ComponentProvider to parent and center the dialog over.
        """
        ...

    @overload
    def editLabel(self, targetSymbol: ghidra.program.model.symbol.Symbol, targetProgram: ghidra.program.model.listing.Program, centeredOverComponent: java.awt.Component) -> None:
        """
        Invokes the dialog to edit an existing label in the given program
        @param targetSymbol the symbol(label) to edit
        @param targetProgram the program containing the symbol
        @param centeredOverComponent the component over which to center the dialog
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getActionContext(self, event: java.awt.event.MouseEvent) -> docking.ActionContext:
        """
        An optional extension point for subclasses to provider action context for the actions used by
         this provider.
        @param event The mouse event used (may be null) to generate a popup menu
        """
        ...

    def getActions(self) -> java.util.Set: ...

    def getBackground(self) -> java.awt.Color:
        """
        Gets the background color of this component.
        @return The background color of this component.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self) -> javax.swing.JComponent: ...

    def getDefaultButton(self) -> javax.swing.JButton:
        """
        Returns the default button for the dialog.
        @return the button
        """
        ...

    def getDefaultSize(self) -> java.awt.Dimension: ...

    def getFocusComponent(self) -> java.awt.Component:
        """
        Returns the component that will receive focus when the dialog is shown
        @return the component
        """
        ...

    def getHelpLocation(self) -> ghidra.util.HelpLocation:
        """
        Returns the help location for this dialog
        @return the help location
        """
        ...

    def getId(self) -> int: ...

    def getInitialLocation(self) -> java.awt.Point:
        """
        Returns the initial location for the dialog or null if none was set
        @return the point
        """
        ...

    def getPreferredSize(self) -> java.awt.Dimension:
        """
        Returns the preferred size of this component.
        @return the preferred size of this component.
        """
        ...

    def getRememberLocation(self) -> bool:
        """
        Returns true if this dialog remembers its location from one invocation to the next.
        @return true if this dialog remembers its location from one invocation to the next.
        """
        ...

    def getRememberSize(self) -> bool:
        """
        Returns true if this dialog remembers its size from one invocation to the next.
        @return true if this dialog remembers its size from one invocation to the next.
        """
        ...

    def getStatusText(self) -> unicode:
        """
        Returns the current status in the dialogs status line
        @return the status text
        """
        ...

    def getTitle(self) -> unicode:
        """
        Returns the title for this component
        @return the title
        """
        ...

    def getUseSharedLocation(self) -> bool:
        """
        Returns true if this dialog uses shared location and size information.
        @return true if this dialog uses shared location and size information.
        @see #setUseSharedLocation(boolean)
        """
        ...

    def hashCode(self) -> int: ...

    def hideTaskMonitorComponent(self) -> None:
        """
        Will hide the progress panel if it was showing.
        @see #showTaskMonitorComponent(String, boolean, boolean)
        """
        ...

    def isModal(self) -> bool:
        """
        Returns true if this component should be displayed in a modal dialog
        @return true if this component should be displayed in a modal dialog
        """
        ...

    def isResizeable(self) -> bool: ...

    def isRunningTask(self) -> bool:
        """
        Returns true if this dialog is running a task.
        @return true if this dialog is running a task.
        """
        ...

    def isShowing(self) -> bool: ...

    def isTransient(self) -> bool:
        """
        Returns true if this dialog is intended to be shown and hidden relatively quickly.  This
         is used to determine if this dialog should be allowed to parent other components.   The
         default is false.
        @return true if this dialog is transient
        """
        ...

    def isVisible(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeAction(self, action: docking.action.DockingActionIf) -> None: ...

    def setBackground(self, color: java.awt.Color) -> None:
        """
        Sets the background on this component.
        @param color The color to set.
        """
        ...

    def setCursor(self, cursor: java.awt.Cursor) -> None:
        """
        Sets the cursor on the root panel for the dialog component.
        @param cursor the cursor to use.
        """
        ...

    def setDefaultButton(self, button: javax.swing.JButton) -> None:
        """
        Sets the button to make "Default" when the dialog is shown.  If no default button is
         desired, then pass <code>null</code> as the <code>button</code> value.
        @param button the button to make default enabled.
        """
        ...

    def setDefaultSize(self, width: int, height: int) -> None: ...

    def setFocusComponent(self, focusComponent: java.awt.Component) -> None:
        """
        Sets the component that should be given focus when the dialog is activated.
         <p>
         Implementation Note:  If the given component is a JButton, then that component will be
         made the default button.
        @param focusComponent the component that should receive default focus.
        @see #setFocusComponent(Component)
        """
        ...

    def setHelpLocation(self, helpLocation: ghidra.util.HelpLocation) -> None:
        """
        Set the help Location for this dialog.
        @param helpLocation the helpLocation for this dialog.
        """
        ...

    def setInitialLocation(self, x: int, y: int) -> None:
        """
        Sets the initial location for the dialog
        @param x the x coordinate
        @param y the y coordinate
        """
        ...

    @overload
    def setMinimumSize(self, minSize: java.awt.Dimension) -> None:
        """
        Sets the minimum size of the dialog
        @param minSize the min size of the dialog
        """
        ...

    @overload
    def setMinimumSize(self, width: int, height: int) -> None: ...

    def setPreferredSize(self, width: int, height: int) -> None:
        """
        Sets the preferred size of the dialog.  Note that if you set the preferred size, the
         dialog will ignore any natural preferred size of your components.
        @param width the preferred width
        @param height the preferred height;
        """
        ...

    def setRememberLocation(self, rememberLocation: bool) -> None:
        """
        Sets this dialog to remember its location from one invocation to the next. The default is to
         remember location.
        @param rememberLocation true to remember, false otherwise.
        """
        ...

    def setRememberSize(self, rememberSize: bool) -> None:
        """
        Sets this dialog to remember its size from one invocation to the next. The default is to
         remember size.
        @param rememberSize true to remember, false otherwise.
        """
        ...

    def setResizable(self, resizeable: bool) -> None:
        """
        Sets the resizable property for the corresponding dialog.
        @param resizeable if false the user will not be able to resize the dialog.
        """
        ...

    def setStatusJustification(self, justification: int) -> None:
        """
        Sets the horizontal position of the status label.
        @param justification One of the following constants
                   defined in <code>SwingConstants</code>:
                   <code>LEFT</code>,
                   <code>CENTER</code> (the default for image-only labels),
                   <code>RIGHT</code>,
        """
        ...

    @overload
    def setStatusText(self, text: unicode) -> None:
        """
        Sets the text in the dialog's status line using the default color
        @param text the text to display in the status line
        """
        ...

    @overload
    def setStatusText(self, message: unicode, type: ghidra.util.MessageType) -> None:
        """
        Sets the text in the dialog's status line using the specified message type to control
         the color.
        @param message the message
        @param type the message type
        """
        ...

    @overload
    def setStatusText(self, message: unicode, type: ghidra.util.MessageType, alert: bool) -> None: ...

    def setTitle(self, title: unicode) -> None:
        """
        Sets the title to be displayed in the dialogs title bar
        @param title the title
        """
        ...

    def setTransient(self, isTransient: bool) -> None:
        """
        Sets this dialog to be transient (see {@link #isTransient()}
        @param isTransient true for transient; false is the default
        """
        ...

    def setUseSharedLocation(self, useSharedLocation: bool) -> None:
        """
        Specifies whether or not this dialog component should use the same remembered location (and
         size) no matter which window this dialog is launched from.  The default is not to use
         shared location and size, which means that there is a remembered location and size for this
         dialog for each window that has launched it (i.e. the window is the parent of the dialog).
        @param useSharedLocation true to share locations
        """
        ...

    def showTaskMonitorComponent(self, localTitle: unicode, hasProgress: bool, canCancel: bool) -> ghidra.util.task.TaskMonitor:
        """
        Shows the progress bar for this dialog.
        @param localTitle the name of the task
        @param hasProgress true if the progress bar should show progress; false to be indeterminate
        @param canCancel true if the task can be cancelled
        @return the {@link TaskMonitor} used by to communicate progress
        @see #hideTaskMonitorComponent()
        """
        ...

    def taskCancelled(self, task: ghidra.util.task.Task) -> None:
        """
        Notification that the task was canceled; the progress panel is
         removed.
        @param task task that was canceled
        """
        ...

    def taskCompleted(self, task: ghidra.util.task.Task) -> None:
        """
        Notification that the given task completed so that the progress
         panel can be removed.
        @param task task that completed
        """
        ...

    def toFront(self) -> None:
        """
        Moves the dialog associated with this provider to the front.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def waitForCurrentTask(self) -> None:
        """
        Blocks the calling thread until the current task has completed; used
         by JUnit tests.
        """
        ...

