from typing import List
import ghidra.framework.plugintool.util
import java.lang


class PluginPackagingProvider(object):
    """
    Provides PluginPackages and plugin descriptions and to clients
    """

    EXPERIMENTAL_ICON: javax.swing.Icon = jar:file:/opt/hostedtoolcache/ghidra/10.4/x64/Ghidra/Framework/Project/lib/Project.jar!/images/applications-science.png
    UNSTABLE_PACKAGE: ghidra.framework.plugintool.util.PluginPackage = Experimental







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getPluginDescription(self, pluginClassName: unicode) -> ghidra.framework.plugintool.util.PluginDescription:
        """
        Returns the plugin description for the given plugin class name
        @param pluginClassName the plugin class name
        @return the description
        """
        ...

    @overload
    def getPluginDescriptions(self) -> List[ghidra.framework.plugintool.util.PluginDescription]:
        """
        Returns all loaded plugin descriptions
        @return the descriptions
        """
        ...

    @overload
    def getPluginDescriptions(self, pluginPackage: ghidra.framework.plugintool.util.PluginPackage) -> List[ghidra.framework.plugintool.util.PluginDescription]:
        """
        Get all plugin descriptions for the given plugin package
        @param pluginPackage the package
        @return the descriptions
        """
        ...

    def getPluginPackages(self) -> List[ghidra.framework.plugintool.util.PluginPackage]:
        """
        Returns all known plugin packages
        @return the plugin packages
        """
        ...

    def getUnstablePluginDescriptions(self) -> List[ghidra.framework.plugintool.util.PluginDescription]:
        """
        Returns all {@link PluginStatus#UNSTABLE} plugin package descriptions
        @return the descriptions
        """
        ...

    def getUnstablePluginPackage(self) -> ghidra.framework.plugintool.util.PluginPackage:
        """
        Returns the plugin package used to house all unstable plugin packages
        @return the package
        """
        ...

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