from typing import List
import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import java.lang


class DeafultPluginPackagingProvider(object, ghidra.framework.plugintool.PluginPackagingProvider):
    """
    The default plugin package provider that uses the PluginsConfiguration to supply packages
    """

    EXPERIMENTAL_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Project/lib/Project.jar!/images/applications-science.png
    UNSTABLE_PACKAGE: ghidra.framework.plugintool.util.PluginPackage = Experimental







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getPluginDescription(self, pluginClassName: unicode) -> ghidra.framework.plugintool.util.PluginDescription: ...

    @overload
    def getPluginDescriptions(self) -> List[ghidra.framework.plugintool.util.PluginDescription]: ...

    @overload
    def getPluginDescriptions(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> List[ghidra.framework.plugintool.util.PluginDescription]: ...

    def getPluginPackages(self) -> List[ghidra.framework.plugintool.util.PluginPackage]: ...

    def getUnstablePluginDescriptions(self) -> List[ghidra.framework.plugintool.util.PluginDescription]: ...

    def getUnstablePluginPackage(self) -> ghidra.framework.plugintool.util.PluginPackage: ...

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
    def pluginDescriptions(self) -> List[object]: ...

    @property
    def pluginPackages(self) -> List[object]: ...

    @property
    def unstablePluginDescriptions(self) -> List[object]: ...

    @property
    def unstablePluginPackage(self) -> ghidra.framework.plugintool.util.PluginPackage: ...