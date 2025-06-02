from typing import List
import ghidra.framework.plugintool.util
import java.lang
import java.util
import org.jdom


class PluginsConfiguration(object):
    """
    This class maintains a collection of all plugin classes that are acceptable for a given tool
     type.  Simple applications with only one plugin type can use the
     DefaultPluginsConfiguration.  More complex tools can support a subset of the available
     plugins. Those tools should create custom subclasses for each tool type, that filter out plugins
     that are not appropriate for that tool type.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getManagedPluginDescriptions(self) -> List[ghidra.framework.plugintool.util.PluginDescription]: ...

    def getPluginClassNames(self, element: org.jdom.Element) -> java.util.Set: ...

    def getPluginDescription(self, className: unicode) -> ghidra.framework.plugintool.util.PluginDescription: ...

    def getPluginDescriptions(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> List[ghidra.framework.plugintool.util.PluginDescription]: ...

    def getPluginNamesByCurrentPackage(self, __a0: List[object]) -> java.util.Set: ...

    def getPluginPackages(self) -> List[ghidra.framework.plugintool.util.PluginPackage]: ...

    def getUnstablePluginDescriptions(self) -> List[ghidra.framework.plugintool.util.PluginDescription]: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def savePluginsToXml(self, __a0: org.jdom.Element, __a1: List[object]) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def managedPluginDescriptions(self) -> List[object]: ...

    @property
    def pluginPackages(self) -> List[object]: ...

    @property
    def unstablePluginDescriptions(self) -> List[object]: ...