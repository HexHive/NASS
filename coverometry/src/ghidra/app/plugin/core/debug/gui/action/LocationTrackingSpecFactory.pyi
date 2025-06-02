from typing import List
import ghidra.app.plugin.core.debug.gui.action
import ghidra.framework.plugintool
import ghidra.util.classfinder
import java.lang
import java.util


class LocationTrackingSpecFactory(ghidra.util.classfinder.ExtensionPoint, object):








    @staticmethod
    def allSuggested(__a0: ghidra.framework.plugintool.PluginTool) -> java.util.Map: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fromConfigName(__a0: unicode) -> ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec: ...

    def getClass(self) -> java.lang.Class: ...

    def getSuggested(self, __a0: ghidra.framework.plugintool.PluginTool) -> List[object]: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def parseSpec(self, __a0: unicode) -> ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

