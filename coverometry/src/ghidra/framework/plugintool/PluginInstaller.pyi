from typing import List
import ghidra.framework.plugintool
import java.lang


class PluginInstaller(object):
    """
    An interface that facilitates the adding and removing of plugins
    """









    def addPlugins(self, __a0: List[object]) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getManagedPlugins(self) -> List[ghidra.framework.plugintool.Plugin]:
        """
        Returns all currently installed plugins
        @return the plugins
        """
        ...

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