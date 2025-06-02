from typing import List
import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import java.lang
import java.util
import org.jdom


class GhidraPluginsConfiguration(ghidra.framework.plugintool.PluginsConfiguration):
    """
    A configuration that allows all general plugins and application plugins.  Plugins that may only
     exist at the application level are filtered out.
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

