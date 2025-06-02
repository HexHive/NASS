from typing import List
import ghidra.framework.model
import ghidra.framework.plugintool
import java.lang
import java.util
import java.util.function


class PluginToolUtils(java.lang.Enum):








    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    @staticmethod
    def getServiceFromRunningCompatibleTool(__a0: ghidra.framework.plugintool.PluginTool, __a1: java.lang.Class) -> object: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def inRunningToolsPreferringActive(__a0: ghidra.framework.plugintool.PluginTool, __a1: java.util.function.Function) -> object: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def openInMostRecentOrLaunchedCompatibleTool(__a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.framework.model.DomainFile) -> ghidra.framework.plugintool.PluginTool: ...

    def ordinal(self) -> int: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.framework.plugintool.PluginToolUtils: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.framework.plugintool.PluginToolUtils]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

