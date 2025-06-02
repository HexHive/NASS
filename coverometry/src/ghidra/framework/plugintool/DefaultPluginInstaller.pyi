from typing import List
import ghidra.framework.plugintool
import java.lang


class DefaultPluginInstaller(object, ghidra.framework.plugintool.PluginInstaller):
    """
    The default plugin installer that uses a tool to install plugins
    """









    def addPlugins(self, __a0: List[object]) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getManagedPlugins(self) -> List[ghidra.framework.plugintool.Plugin]: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removePlugins(self, __a0: List[object]) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def managedPlugins(self) -> List[object]: ...