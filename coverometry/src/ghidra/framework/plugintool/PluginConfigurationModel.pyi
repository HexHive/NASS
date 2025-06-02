from typing import List
import ghidra.framework.plugintool.util
import java.lang
import utility.function


class PluginConfigurationModel(object):




    @overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool): ...

    @overload
    def __init__(self, pluginInstaller: ghidra.framework.plugintool.PluginInstaller, pluginPackagingProvider: ghidra.framework.plugintool.PluginPackagingProvider): ...



    def addPlugin(self, pluginDescription: ghidra.framework.plugintool.util.PluginDescription) -> None: ...

    def addSupportedPlugins(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getAllPluginDescriptions(self) -> List[ghidra.framework.plugintool.util.PluginDescription]: ...

    def getClass(self) -> java.lang.Class: ...

    def getDependencies(self, pd: ghidra.framework.plugintool.util.PluginDescription) -> List[ghidra.framework.plugintool.util.PluginDescription]:
        """
        Return the descriptions of the plugins that are dependent on some service that the plugin
         corresponding to the given PluginDescription provides.
        @param pd PluginDescription of the plugin
        @return the descriptions
        """
        ...

    def getPackageState(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> ghidra.framework.plugintool.util.PluginPackageState: ...

    def getPluginDescriptions(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> List[ghidra.framework.plugintool.util.PluginDescription]: ...

    def getPluginPackages(self) -> List[ghidra.framework.plugintool.util.PluginPackage]: ...

    def hasDependencies(self, pluginDependency: ghidra.framework.plugintool.util.PluginDescription) -> bool:
        """
        Return whether the plugin corresponding to the given PluginDescription
         has other plugins depending on a service it provides.
        @param pluginDependency PluginDescription of the plugin
        @return true if the plugin corresponding to the given PluginDescription
         has at least one plugin depending on a service it provides
        """
        ...

    def hasOnlyUnstablePlugins(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> bool: ...

    def hashCode(self) -> int: ...

    def isLoaded(self, pluginDescription: ghidra.framework.plugintool.util.PluginDescription) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeAllPlugins(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> None: ...

    def removePlugin(self, pluginDescription: ghidra.framework.plugintool.util.PluginDescription) -> None: ...

    def setChangeCallback(self, listener: utility.function.Callback) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def allPluginDescriptions(self) -> List[object]: ...

    @property
    def changeCallback(self) -> None: ...  # No getter available.

    @changeCallback.setter
    def changeCallback(self, value: utility.function.Callback) -> None: ...

    @property
    def pluginPackages(self) -> List[object]: ...