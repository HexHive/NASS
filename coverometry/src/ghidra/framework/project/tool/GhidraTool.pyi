from typing import List
import docking
import docking.action
import docking.actions
import docking.util.image
import ghidra.framework.cmd
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.framework.plugintool.dialog
import ghidra.framework.plugintool.util
import ghidra.util.task
import java.awt
import java.beans
import java.lang
import java.net
import java.util
import javax.swing
import org.jdom


class GhidraTool(ghidra.framework.plugintool.PluginTool):
    """
    Tool created by the workspace when the user chooses to create a new
     tool. Its ToolConfigProvider shows all Plugins with the exception of
     those plugins that can be added to the Front End tool only.
    """

    autoSave: bool



    @overload
    def __init__(self, project: ghidra.framework.model.Project, name: unicode):
        """
        Construct a new Ghidra Tool.
        @param project the project associated with the tool
        @param name the name of the tool
        """
        ...

    @overload
    def __init__(self, project: ghidra.framework.model.Project, template: ghidra.framework.project.tool.GhidraToolTemplate):
        """
        Construct a new GhidraTool using an existing template.
        @param project project that is the associated with the tool.
        @param template the template to use when creating the tool
        """
        ...



    def accept(self, url: java.net.URL) -> bool:
        """
        Request tool to accept specified URL.  Acceptance of URL depends greatly on the plugins
         configured into tool.  If no plugin accepts URL it will be rejected and false returned.
         If a plugin can accept the specified URL it will attempt to process and return true if
         successful.  The user may be prompted if connecting to the URL requires user authentication.
        @param url read-only resource URL
        @return true if URL accepted and processed else false
        """
        ...

    def acceptDomainFiles(self, data: List[ghidra.framework.model.DomainFile]) -> bool: ...

    def addAction(self, action: docking.action.DockingActionIf) -> None: ...

    def addComponentProvider(self, provider: docking.ComponentProvider, show: bool) -> None: ...

    def addContextListener(self, listener: docking.DockingContextListener) -> None: ...

    def addEventListener(self, eventClass: java.lang.Class, listener: ghidra.framework.plugintool.util.PluginEventListener) -> None: ...

    def addListenerForAllPluginEvents(self, listener: ghidra.framework.plugintool.util.PluginEventListener) -> None: ...

    def addLocalAction(self, provider: docking.ComponentProvider, action: docking.action.DockingActionIf) -> None: ...

    @overload
    def addPlugin(self, className: unicode) -> None:
        """
        Add a plugin to the tool.
        @param className name of the plugin class, e.g., "MyPlugin.class.getName()"
        @throws PluginException if the plugin could not be constructed, or
         there was problem executing its init() method, or if a plugin of this
         class already exists in the tool
        """
        ...

    @overload
    def addPlugin(self, p: ghidra.framework.plugintool.Plugin) -> None: ...

    @overload
    def addPlugins(self, classNames: List[unicode]) -> None:
        """
        Add plugins to the tool.
        @param classNames array of plugin class names
        @throws PluginException if a plugin could not be constructed, or
         there was problem executing its init() method, or if a plugin of this
         class already exists in the tool
        @deprecated use {@link #addPlugins(Collection)}
        """
        ...

    @overload
    def addPlugins(self, classNames: java.util.Collection) -> None:
        """
        Add plugins to the tool.
        @param classNames collection of plugin class names
        @throws PluginException if a plugin could not be constructed, or
         there was problem executing its init() method, or if a plugin of this
         class already exists in the tool
        """
        ...

    def addPopupActionProvider(self, provider: docking.actions.PopupActionProvider) -> None: ...

    def addPropertyChangeListener(self, l: java.beans.PropertyChangeListener) -> None: ...

    def addServiceListener(self, listener: ghidra.framework.plugintool.util.ServiceListener) -> None: ...

    def addStatusComponent(self, c: javax.swing.JComponent, addBorder: bool, rightSide: bool) -> None:
        """
        Add a status component to the tool.
        @param c component to add
        @param addBorder true if a border should be added to the component
        @param rightSide true if the component should be placed in the right side of the tool
        """
        ...

    def addToolListener(self, listener: ghidra.framework.model.ToolListener) -> None: ...

    def beep(self) -> None:
        """
        A convenience method to make an attention-grabbing noise to the user
        """
        ...

    def canCloseDomainFile(self, domainFile: ghidra.framework.model.DomainFile) -> bool: ...

    def canCloseDomainObject(self, domainObject: ghidra.framework.model.DomainObject) -> bool:
        """
        Can the domain object be closed?
         <br>Note: This forces plugins to terminate any tasks they have running for the
         indicated domain object and apply any unsaved data to the domain object. If they can't do
         this or the user cancels then this returns false.
        @param domainObject the domain object to check
        @return false any of the plugins reports that the domain object
         should not be closed
        """
        ...

    def cancelCurrentTask(self) -> None:
        """
        Cancel the current task in the tool.
        """
        ...

    def clearLastEvents(self) -> None:
        """
        Clear the list of events that were last generated.
        """
        ...

    def clearStatusInfo(self) -> None: ...

    def close(self) -> None:
        """
        Closes this tool, possibly with input from the user. The following conditions are checked
         and can prompt the user for more info and allow them to cancel the close.
         <OL>
         	<LI>Running tasks. Closing with running tasks could lead to data loss.
          <LI>Plugins get asked if they can be closed. They may prompt the user to resolve
          some plugin specific state.
         	<LI>The user is prompted to save any data changes.
         	<LI>Tools are saved, possibly asking the user to resolve any conflicts caused by
          changing multiple instances of the same tool in different ways.
         	<LI>If all the above conditions passed, the tool is closed and disposed.
         </OL>
        """
        ...

    def contextChanged(self, provider: docking.ComponentProvider) -> None: ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def execute(self, task: ghidra.util.task.Task) -> None:
        """
        Launch the task in a new thread
        @param task task to run in a new thread
        """
        ...

    @overload
    def execute(self, task: ghidra.util.task.Task, delay: int) -> None:
        """
        Launch the task in a new thread
        @param task task to run in a new thread
        @param delay number of milliseconds to delay the display of task monitor dialog
        """
        ...

    @overload
    def execute(self, command: ghidra.framework.cmd.Command, obj: ghidra.framework.model.DomainObject) -> bool:
        """
        Call the applyTo() method on the given command to make some change to
         the domain object; the command is done in the AWT thread, therefore,
         the command that is to be executed should be a relatively quick operation
         so that the event queue does not appear to "hang." For lengthy
         operations, the command should be done in a background task.
        @param command command to apply
        @param obj domain object that the command will be applied to
        @return status of the command's applyTo() method
        @see #executeBackgroundCommand(BackgroundCommand, UndoableDomainObject)
        """
        ...

    def executeBackgroundCommand(self, cmd: ghidra.framework.cmd.BackgroundCommand, obj: ghidra.framework.model.UndoableDomainObject) -> None:
        """
        Start a new thread that will call the given command's applyTo()
         method to make some change in the domain object. This method should
         be called for an operation that could potentially take a long time to
         complete.
        @param cmd command that will be executed in another thread (not the
         AWT Thread)
        @param obj domain object that the command will be applied to
        """
        ...

    def firePluginEvent(self, event: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def getActiveComponentProvider(self) -> docking.ComponentProvider: ...

    def getActiveWindow(self) -> java.awt.Window: ...

    def getAllActions(self) -> java.util.Set: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponentProvider(self, name: unicode) -> docking.ComponentProvider: ...

    def getConsumedToolEventNames(self) -> List[unicode]: ...

    def getDockingActionsByOwnerName(self, owner: unicode) -> java.util.Set: ...

    def getDomainFiles(self) -> List[ghidra.framework.model.DomainFile]: ...

    def getIcon(self) -> javax.swing.ImageIcon: ...

    def getIconURL(self) -> docking.util.image.ToolIconURL: ...

    def getInstanceName(self) -> unicode: ...

    def getLocation(self) -> java.awt.Point:
        """
        Return the location of this tool's frame on the screen.
        @return location of this tool's frame
        """
        ...

    def getManagePluginsDialog(self) -> ghidra.framework.plugintool.dialog.ManagePluginsDialog:
        """
        Returns the manage plugins dialog that is currently
         being used.
        @return the current manage plugins dialog
        """
        ...

    def getManagedPlugins(self) -> List[ghidra.framework.plugintool.Plugin]:
        """
        Return a list of plugins in the tool
        @return list of plugins in the tool
        """
        ...

    def getName(self) -> unicode: ...

    @overload
    def getOptions(self) -> List[ghidra.framework.options.ToolOptions]:
        """
        Get all options.
        @return zero-length array if no options exist.
        """
        ...

    @overload
    def getOptions(self, categoryName: unicode) -> ghidra.framework.options.ToolOptions: ...

    def getPluginsConfiguration(self) -> ghidra.framework.plugintool.PluginsConfiguration: ...

    def getProject(self) -> ghidra.framework.model.Project:
        """
        Get the project associated with this tool.  Null will be returned if there is no
         project open or if this tool does not use projects.
        @return null if there is no open project
        """
        ...

    def getProjectManager(self) -> ghidra.framework.model.ProjectManager:
        """
        Returns the project manager associated with this tool.

         <P>Null will be returned if this tool does not use projects.
        @return the project manager associated with this tool
        """
        ...

    def getProviderWindow(self, provider: docking.ComponentProvider) -> java.awt.Window: ...

    def getService(self, c: java.lang.Class) -> object: ...

    def getServices(self, c: java.lang.Class) -> List[object]:
        """
        Get the objects that implement the given service.
        @param c service class
        @return array of Objects that implement the service, c.
        """
        ...

    def getSize(self) -> java.awt.Dimension:
        """
        Return the dimension of this tool's frame.
        @return dimension of this tool's frame
        """
        ...

    def getStatusInfo(self) -> unicode: ...

    def getSupportedDataTypes(self) -> java.lang.Class: ...

    def getToolActions(self) -> docking.actions.DockingToolActions: ...

    def getToolEventNames(self) -> List[unicode]: ...

    def getToolFrame(self) -> javax.swing.JFrame: ...

    def getToolName(self) -> unicode: ...

    def getToolServices(self) -> ghidra.framework.model.ToolServices:
        """
        Returns an object that provides fundamental services that plugins can use
        @return the services instance
        """
        ...

    def getToolTemplate(self, includeConfigState: bool) -> ghidra.framework.model.ToolTemplate: ...

    def getTransientState(self) -> ghidra.framework.plugintool.util.TransientToolState: ...

    def getUndoRedoToolState(self, domainObject: ghidra.framework.model.DomainObject) -> ghidra.framework.plugintool.util.UndoRedoToolState: ...

    def getWindowManager(self) -> docking.DockingWindowManager: ...

    def hasConfigChanged(self) -> bool: ...

    def hasOptions(self, category: unicode) -> bool:
        """
        Return true if there is an options category with the given name
        @param category name of the options set
        @return true if there is an options category with the given name
        """
        ...

    def hasToolListeners(self) -> bool:
        """
        Returns true if there is at least one tool listening to this tool's plugin events
        @return true if there is at least one tool listening to this tool's plugin events
        """
        ...

    def hasUnsavedData(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isActive(self, provider: docking.ComponentProvider) -> bool: ...

    def isConfigurable(self) -> bool: ...

    def isExecutingCommand(self) -> bool:
        """
        Return whether there is a command being executed
        @return true if there is a command being executed
        """
        ...

    def isRestoringDataState(self) -> bool: ...

    def isService(self, serviceInterface: java.lang.Class) -> bool:
        """
        Returns true if the specified <code>serviceInterface</code>
         is a valid service that exists in this tool.
        @param serviceInterface the service interface
        @return true if the specified <code>serviceInterface</code>
        """
        ...

    @overload
    def isVisible(self) -> bool: ...

    @overload
    def isVisible(self, provider: docking.ComponentProvider) -> bool: ...

    def isWindowsOnTop(self) -> bool:
        """
        Return the value of the Tool option (GhidraOptions.OPTION_DOCKING_WINDOWS_ON_TOP)
         for whether docked windows will always be shown on top of their parent windows.
        @return value of the Tool option, GhidraOptions.OPTION_DOCKING_WINDOWS_ON_TOP
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def prepareToSave(self, dobj: ghidra.framework.model.DomainObject) -> None:
        """
        Called when the domain object is about to be saved; this allows any plugin that has
         a cache to flush out to the domain object.
        @param dobj domain object that is about to be saved
        """
        ...

    def processToolEvent(self, toolEvent: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def putInstanceName(self, newInstanceName: unicode) -> None: ...

    def refreshKeybindings(self) -> None: ...

    def registerDefaultContextProvider(self, type: java.lang.Class, provider: docking.action.ActionContextProvider) -> None:
        """
        Registers an action context provider as the default provider for a specific action
         context type. Note that this registers a default provider for exactly
         that type and not a subclass of that type. If the provider want to support a hierarchy of
         types, then it must register separately for each type. See {@link ActionContext} for details
         on how the action context system works.
        @param type the ActionContext class to register a default provider for
        @param provider the ActionContextProvider that provides default tool context for actions
         that consume the given ActionContext type
        """
        ...

    def registerOptionsNameChange(self, oldName: unicode, newName: unicode) -> None:
        """
        Updates saved options from an old name to a new name.  NOTE: this must be called before
         any calls to register or get options.
        @param oldName the old name of the options.
        @param newName the new name of the options.
        """
        ...

    def removeAction(self, action: docking.action.DockingActionIf) -> None: ...

    def removeComponentProvider(self, provider: docking.ComponentProvider) -> None: ...

    def removeContextListener(self, listener: docking.DockingContextListener) -> None: ...

    def removeEventListener(self, eventClass: java.lang.Class, listener: ghidra.framework.plugintool.util.PluginEventListener) -> None: ...

    def removeListenerForAllPluginEvents(self, listener: ghidra.framework.plugintool.util.PluginEventListener) -> None: ...

    def removeLocalAction(self, provider: docking.ComponentProvider, action: docking.action.DockingActionIf) -> None: ...

    @overload
    def removePlugins(self, plugins: List[ghidra.framework.plugintool.Plugin]) -> None:
        """
        Remove the array of plugins from the tool.
        @param plugins array of plugins to remove
        @deprecated use {@link #removePlugins(List)}
        """
        ...

    @overload
    def removePlugins(self, __a0: List[object]) -> None: ...

    def removePopupActionProvider(self, provider: docking.actions.PopupActionProvider) -> None: ...

    def removePreferenceState(self, name: unicode) -> None: ...

    def removePropertyChangeListener(self, l: java.beans.PropertyChangeListener) -> None: ...

    def removeServiceListener(self, listener: ghidra.framework.plugintool.util.ServiceListener) -> None: ...

    def removeStatusComponent(self, c: javax.swing.JComponent) -> None:
        """
        Remove the status component.
        @param c status component to remove
        """
        ...

    def removeToolListener(self, listener: ghidra.framework.model.ToolListener) -> None: ...

    def restoreDataStateFromXml(self, root: org.jdom.Element) -> None: ...

    def restoreWindowingDataFromXml(self, rootElement: org.jdom.Element) -> None: ...

    def saveDataStateToXml(self, savingProject: bool) -> org.jdom.Element: ...

    def saveToXml(self, includeConfigState: bool) -> org.jdom.Element: ...

    def saveTool(self) -> None:
        """
        Save this tool's configuration.
        """
        ...

    def saveToolAs(self) -> bool:
        """
        Triggers a 'Save As' dialog that allows the user to save off the tool under a different
         name.  This returns true if the user performed a save.
        @return true if a save happened
        """
        ...

    def saveToolToToolTemplate(self) -> ghidra.framework.model.ToolTemplate: ...

    def saveWindowingDataToXml(self) -> org.jdom.Element: ...

    def scheduleFollowOnCommand(self, cmd: ghidra.framework.cmd.BackgroundCommand, obj: ghidra.framework.model.UndoableDomainObject) -> None:
        """
        Add the given background command to a queue that is processed after the
         main background command completes.
        @param cmd background command to submit
        @param obj the domain object to be modified by the command.
        """
        ...

    def setConfigChanged(self, changed: bool) -> None: ...

    def setDefaultComponent(self, provider: docking.ComponentProvider) -> None:
        """
        Sets the provider that should get the default focus when no component has focus.
        @param provider the provider that should get the default focus when no component has focus.
        """
        ...

    def setIconURL(self, newIconURL: docking.util.image.ToolIconURL) -> None: ...

    def setLocation(self, x: int, y: int) -> None:
        """
        Set the location of this tool's frame on the screen.
        @param x screen x coordinate
        @param y screen y coordinate
        """
        ...

    @overload
    def setMenuGroup(self, menuPath: List[unicode], group: unicode) -> None:
        """
        Set the menu group associated with a cascaded submenu. This allows a cascading menu item to
         be grouped with a specific set of actions. The default group for a cascaded submenu is the
         name of the submenu.
        @param menuPath menu name path where the last element corresponds to the specified group
                    name.
        @param group group name
        @see #setMenuGroup(String[], String, String)
        """
        ...

    @overload
    def setMenuGroup(self, menuPath: List[unicode], group: unicode, menuSubGroup: unicode) -> None: ...

    def setSize(self, width: int, height: int) -> None:
        """
        Sets the size of the tool's main window
        @param width width in pixels
        @param height height in pixels
        """
        ...

    @overload
    def setStatusInfo(self, text: unicode) -> None: ...

    @overload
    def setStatusInfo(self, text: unicode, beep: bool) -> None: ...

    def setSubTitle(self, subTitle: unicode) -> None:
        """
        Sets the subtitle on the tool; the subtitle is extra text in the title.
        @param subTitle the subtitle to display on the tool
        """
        ...

    def setToolName(self, name: unicode) -> None: ...

    def setUnconfigurable(self) -> None: ...

    def setVisible(self, visible: bool) -> None: ...

    def setWindowsOnTop(self, b: bool) -> None:
        """
        Set the Tool option (GhidraOptions.OPTION_DOCKING_WINDOWS_ON_TOP)
         for whether a docked window will always be shown on top of its parent window.
        @param b true means that the docked window will always appear on top of its
         parent window; false means to allow the docked window to be "hidden" under its
         parent dialog
        """
        ...

    def shouldSave(self) -> bool: ...

    def showComponentHeader(self, provider: docking.ComponentProvider, b: bool) -> None:
        """
        Set whether a component's header should be shown; the header is the component that
         is dragged in order to move the component within the tool, or out of the tool
         into a separate window
        @param provider provider of the visible component in the tool
        @param b true means to show the header
        """
        ...

    def showComponentProvider(self, provider: docking.ComponentProvider, visible: bool) -> None: ...

    def showConfig(self, addSaveActions: bool, isNewTool: bool) -> None:
        """
        Displays the manage plugins dialog.
        @param addSaveActions if true show save actions
        @param isNewTool true if creating a new tool
        """
        ...

    @overload
    def showDialog(self, dialogComponent: docking.DialogComponentProvider) -> None: ...

    @overload
    def showDialog(self, dialogComponent: docking.DialogComponentProvider, centeredOnProvider: docking.ComponentProvider) -> None:
        """
        Shows the dialog using the window containing the given componentProvider as its parent window.
         Remembers the last location and size of this dialog for the next time it is shown.
        @param dialogComponent the DialogComponentProvider object to be shown in a dialog.
        @param centeredOnProvider the component provider that is used to find a parent window for this dialog.
         The dialog is centered on this component provider's component.
        """
        ...

    @overload
    def showDialog(self, dialogComponent: docking.DialogComponentProvider, centeredOnComponent: java.awt.Component) -> None:
        """
        Shows the dialog using the tool's parent frame, but centers the dialog on the given
         component
        @param dialogComponent the DialogComponentProvider object to be shown in a dialog.
        @param centeredOnComponent the component on which to center the dialog.
        """
        ...

    def showDialogOnActiveWindow(self, dialogComponent: docking.DialogComponentProvider) -> None:
        """
        Shows the dialog using the tool's currently active window as a parent.  Also,
         remembers any size and location adjustments made by the user for the next
         time the dialog is shown.
        @param dialogComponent the DialogComponentProvider object to be shown in a dialog.
        @deprecated dialogs are now always shown over the active window when possible
        """
        ...

    def showEditWindow(self, defaultText: unicode, comp: java.awt.Component, rect: java.awt.Rectangle, listener: docking.EditListener) -> None:
        """
        Display an text edit box on top of the specified component.
        @param defaultText initial text to be displayed in edit box
        @param comp component over which the edit box will be placed
        @param rect specifies the bounds of the edit box relative to the
         component.  The height is ignored.  The default text field height
         is used as the preferred height.
        @param listener when the edit is complete, this listener is notified
         with the new text.  The edit box is dismissed prior to notifying
         the listener.
        """
        ...

    def showExtensions(self) -> None:
        """
        Displays the extensions installation dialog.
        """
        ...

    def threadIsBackgroundTaskThread(self) -> bool:
        """
        @return true if the current thread group or its ancestors is
         a member of this tools background task thread group, else false
        """
        ...

    @overload
    def toFront(self) -> None: ...

    @overload
    def toFront(self, provider: docking.ComponentProvider) -> None: ...

    def toString(self) -> unicode: ...

    def unregisterDefaultContextProvider(self, type: java.lang.Class, provider: docking.action.ActionContextProvider) -> None:
        """
        Removes the default provider for the given ActionContext type.
        @param type the subclass of ActionContext to remove a provider for
        @param provider the ActionContextProvider to remove for the given ActionContext type
        """
        ...

    def updateTitle(self, provider: docking.ComponentProvider) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def toolName(self) -> unicode: ...

    @toolName.setter
    def toolName(self, value: unicode) -> None: ...

    @property
    def visible(self) -> bool: ...

    @visible.setter
    def visible(self, value: bool) -> None: ...