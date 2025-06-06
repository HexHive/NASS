from typing import List
import ghidra.app.plugin.core.debug
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import ghidra.program.model.address
import ghidra.trace.model.time.schedule
import java.lang
import java.net
import java.util.concurrent


class DebuggerTraceViewDiffPlugin(ghidra.app.plugin.core.debug.AbstractDebuggerPlugin):




    def __init__(self, __a0: ghidra.framework.plugintool.PluginTool): ...



    def accept(self, __a0: java.net.URL) -> bool: ...

    def acceptData(self, __a0: List[ghidra.framework.model.DomainFile]) -> bool: ...

    @staticmethod
    def blockFor(__a0: int, __a1: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange: ...

    def dataStateRestoreCompleted(self) -> None: ...

    def dependsUpon(self, __a0: ghidra.framework.plugintool.Plugin) -> bool: ...

    def endComparison(self) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def eventSent(self, __a0: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def firePluginEvent(self, __a0: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def getData(self) -> List[ghidra.framework.model.DomainFile]: ...

    def getDiffs(self) -> ghidra.program.model.address.AddressSetView: ...

    def getMissingRequiredServices(self) -> List[object]: ...

    def getName(self) -> unicode: ...

    def getNextDiff(self) -> ghidra.program.model.address.Address: ...

    def getPluginDescription(self) -> ghidra.framework.plugintool.util.PluginDescription: ...

    def getPrevDiff(self) -> ghidra.program.model.address.Address: ...

    def getSupportedDataTypes(self) -> List[java.lang.Class]: ...

    def getTool(self) -> ghidra.framework.plugintool.PluginTool: ...

    def getTransientState(self) -> object: ...

    def getUndoRedoState(self, __a0: ghidra.framework.model.DomainObject) -> object: ...

    def gotoNextDiff(self) -> bool: ...

    def gotoPrevDiff(self) -> bool: ...

    def hasMissingRequiredService(self) -> bool: ...

    def hasNextDiff(self) -> bool: ...

    def hasPrevDiff(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isDisposed(self) -> bool: ...

    @staticmethod
    def lenRemainsBlock(__a0: int, __a1: long) -> int: ...

    @overload
    @staticmethod
    def maxOfBlock(__a0: int, __a1: long) -> long: ...

    @overload
    @staticmethod
    def maxOfBlock(__a0: int, __a1: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address: ...

    @staticmethod
    def minOfBlock(__a0: int, __a1: long) -> long: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def processEvent(self, __a0: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def readConfigState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    def readDataState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    def restoreTransientState(self, __a0: object) -> None: ...

    def restoreUndoRedoState(self, __a0: ghidra.framework.model.DomainObject, __a1: object) -> None: ...

    def serviceAdded(self, __a0: java.lang.Class, __a1: object) -> None: ...

    def serviceRemoved(self, __a0: java.lang.Class, __a1: object) -> None: ...

    def startComparison(self, __a0: ghidra.trace.model.time.schedule.TraceSchedule) -> java.util.concurrent.CompletableFuture: ...

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
    def diffs(self) -> ghidra.program.model.address.AddressSetView: ...

    @property
    def nextDiff(self) -> ghidra.program.model.address.Address: ...

    @property
    def prevDiff(self) -> ghidra.program.model.address.Address: ...