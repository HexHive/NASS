from typing import List
import docking.options
import ghidra.framework.options
import ghidra.framework.plugintool
import java.lang
import org.jdom


class OptionsManager(object, docking.options.OptionsService, ghidra.framework.options.OptionsChangeListener):
    """
    Created by PluginTool to manage the set of Options for each category.
    """





    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor
        @param tool associated with this OptionsManager
        """
        ...



    def deregisterOwner(self, ownerPlugin: ghidra.framework.plugintool.Plugin) -> None:
        """
        Deregister the owner from the options; if options are empty, then
         remove the options from the map.
        @param ownerPlugin the owner plugin
        """
        ...

    def dispose(self) -> None: ...

    def editOptions(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getConfigState(self) -> org.jdom.Element:
        """
        Write this object out; first remove any unused options so they
         do not hang around.
        @return XML element containing the state of all the options
        """
        ...

    @overload
    def getOptions(self) -> List[ghidra.framework.options.ToolOptions]: ...

    @overload
    def getOptions(self, category: unicode) -> ghidra.framework.options.ToolOptions: ...

    def hasOptions(self, category: unicode) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def optionsChanged(self, options: ghidra.framework.options.ToolOptions, name: unicode, oldValue: object, newValue: object) -> None: ...

    def registerOptionNameChanged(self, oldName: unicode, newName: unicode) -> None:
        """
        Updates saved options from an old name to a new name.  NOTE: this must be called before
         any calls to register or get options.
        @param oldName the old name of the options.
        @param newName the new name of the options.
        """
        ...

    def removeUnusedOptions(self) -> None: ...

    def setConfigState(self, root: org.jdom.Element) -> None:
        """
        Restore Options objects using the given XML Element.
        @param root element to use to restore the Options objects
        """
        ...

    def showOptionsDialog(self, category: unicode, filterText: unicode) -> None: ...

    def toString(self) -> unicode: ...

    def validateOptions(self) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def configState(self) -> org.jdom.Element: ...

    @configState.setter
    def configState(self, value: org.jdom.Element) -> None: ...

    @property
    def options(self) -> List[ghidra.framework.options.ToolOptions]: ...