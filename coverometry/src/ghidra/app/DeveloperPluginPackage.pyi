import ghidra.framework.plugintool.util
import java.lang
import javax.swing


class DeveloperPluginPackage(ghidra.framework.plugintool.util.PluginPackage):
    NAME: unicode = u'Developer'



    def __init__(self): ...



    @overload
    def compareTo(self, other: ghidra.framework.plugintool.util.PluginPackage) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def exists(packageName: unicode) -> bool:
        """
        Returns true if the system has found a plugin package for the given name
        @param packageName the package name
        @return true if the system has found a plugin package for the given name
        """
        ...

    def getActivationLevel(self) -> ghidra.framework.plugintool.util.PluginStatus: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getIcon(self) -> javax.swing.Icon: ...

    def getName(self) -> unicode: ...

    @staticmethod
    def getPluginPackage(packageName: unicode) -> ghidra.framework.plugintool.util.PluginPackage:
        """
        Returns the existing plugin package with the given name.  If no package exists, then the
         {@link MiscellaneousPluginPackage} will be returned.
        @param packageName the package name
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
    def activationLevel(self) -> ghidra.framework.plugintool.util.PluginStatus: ...