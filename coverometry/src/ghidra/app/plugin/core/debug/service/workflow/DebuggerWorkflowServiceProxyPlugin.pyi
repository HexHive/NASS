from typing import List
import ghidra.app.services
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import java.lang
import java.net
import java.util


class DebuggerWorkflowServiceProxyPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.DebuggerWorkflowService):




    def __init__(self, __a0: ghidra.framework.plugintool.PluginTool): ...



    def accept(self, __a0: java.net.URL) -> bool: ...

    def acceptData(self, __a0: List[ghidra.framework.model.DomainFile]) -> bool: ...

    def dataStateRestoreCompleted(self) -> None: ...

    def dependsUpon(self, __a0: ghidra.framework.plugintool.Plugin) -> bool: ...

    def disableBots(self, __a0: java.util.Set) -> None: ...

    def enableBots(self, __a0: java.util.Set) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def eventSent(self, __a0: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def firePluginEvent(self, __a0: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def getAllBots(self) -> java.util.Set: ...

    def getClass(self) -> java.lang.Class: ...

    def getData(self) -> List[ghidra.framework.model.DomainFile]: ...

    def getDisabledBots(self) -> java.util.Set: ...

    def getEnabledBots(self) -> java.util.Set: ...

    def getMissingRequiredServices(self) -> List[object]: ...

    def getName(self) -> unicode: ...

    def getPluginDescription(self) -> ghidra.framework.plugintool.util.PluginDescription: ...

    def getSupportedDataTypes(self) -> List[java.lang.Class]: ...

    def getTool(self) -> ghidra.framework.plugintool.PluginTool: ...

    def getTransientState(self) -> object: ...

    def getUndoRedoState(self, __a0: ghidra.framework.model.DomainObject) -> object: ...

    def hasMissingRequiredService(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isDisposed(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def processEvent(self, __a0: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def readConfigState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    def readDataState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    def restoreTransientState(self, __a0: object) -> None: ...

    def restoreUndoRedoState(self, __a0: ghidra.framework.model.DomainObject, __a1: object) -> None: ...

    def serviceAdded(self, __a0: java.lang.Class, __a1: object) -> None: ...

    def serviceRemoved(self, __a0: java.lang.Class, __a1: object) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeConfigState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    def writeDataState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    @property
    def allBots(self) -> java.util.Set: ...

    @property
    def disabledBots(self) -> java.util.Set: ...

    @property
    def enabledBots(self) -> java.util.Set: ...