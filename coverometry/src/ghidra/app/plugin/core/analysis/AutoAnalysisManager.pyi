from typing import List
import generic.concurrent
import ghidra.app.plugin.core.analysis
import ghidra.app.services
import ghidra.app.util.importer
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.task
import java.lang
import java.util


class AutoAnalysisManager(object, ghidra.framework.model.DomainObjectListener):








    def addListener(self, __a0: ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener) -> None: ...

    def addTool(self, __a0: ghidra.framework.plugintool.PluginTool) -> None: ...

    def blockAdded(self, __a0: ghidra.program.model.address.AddressSetView) -> None: ...

    def cancelQueuedTasks(self) -> None: ...

    @overload
    def codeDefined(self, __a0: ghidra.program.model.address.Address) -> None: ...

    @overload
    def codeDefined(self, __a0: ghidra.program.model.address.AddressSetView) -> None: ...

    @overload
    def createFunction(self, __a0: ghidra.program.model.address.Address, __a1: bool) -> None: ...

    @overload
    def createFunction(self, __a0: ghidra.program.model.address.AddressSetView, __a1: bool) -> None: ...

    @overload
    def createFunction(self, __a0: ghidra.program.model.address.AddressSetView, __a1: bool, __a2: ghidra.app.services.AnalysisPriority) -> None: ...

    def dataDefined(self, __a0: ghidra.program.model.address.AddressSetView) -> None: ...

    @overload
    def disassemble(self, __a0: ghidra.program.model.address.Address) -> None: ...

    @overload
    def disassemble(self, __a0: ghidra.program.model.address.AddressSetView) -> None: ...

    @overload
    def disassemble(self, __a0: ghidra.program.model.address.AddressSetView, __a1: ghidra.app.services.AnalysisPriority) -> None: ...

    def dispose(self) -> None: ...

    def domainObjectChanged(self, __a0: ghidra.framework.model.DomainObjectChangedEvent) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def externalAdded(self, __a0: ghidra.program.model.address.Address) -> None: ...

    @overload
    def functionDefined(self, __a0: ghidra.program.model.address.Address) -> None: ...

    @overload
    def functionDefined(self, __a0: ghidra.program.model.address.AddressSetView) -> None: ...

    @overload
    def functionModifierChanged(self, __a0: ghidra.program.model.address.Address) -> None: ...

    @overload
    def functionModifierChanged(self, __a0: ghidra.program.model.address.AddressSetView) -> None: ...

    @overload
    def functionSignatureChanged(self, __a0: ghidra.program.model.address.Address) -> None: ...

    @overload
    def functionSignatureChanged(self, __a0: ghidra.program.model.address.AddressSetView) -> None: ...

    @staticmethod
    def getAnalysisManager(__a0: ghidra.program.model.listing.Program) -> ghidra.app.plugin.core.analysis.AutoAnalysisManager: ...

    def getAnalysisTool(self) -> ghidra.framework.plugintool.PluginTool: ...

    def getAnalyzer(self, __a0: unicode) -> ghidra.app.services.Analyzer: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataTypeManagerService(self) -> ghidra.app.services.DataTypeManagerService: ...

    def getMessageLog(self) -> ghidra.app.util.importer.MessageLog: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getProtectedLocations(self) -> ghidra.program.model.address.AddressSetView: ...

    @staticmethod
    def getSharedAnalsysThreadPool() -> generic.concurrent.GThreadPool: ...

    def getTaskTime(self, __a0: java.util.Map, __a1: unicode) -> long: ...

    def getTaskTimesString(self) -> unicode: ...

    def getTimedTasks(self) -> List[unicode]: ...

    def getTotalTimeInMillis(self) -> int: ...

    @staticmethod
    def hasAutoAnalysisManager(__a0: ghidra.program.model.listing.Program) -> bool: ...

    def hashCode(self) -> int: ...

    @overload
    def initializeOptions(self) -> None: ...

    @overload
    def initializeOptions(self, __a0: ghidra.framework.options.Options) -> None: ...

    def isAnalyzing(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def reAnalyzeAll(self, __a0: ghidra.program.model.address.AddressSetView) -> None: ...

    def registerAnalyzerOptions(self) -> None: ...

    def registerOptions(self) -> None: ...

    def removeListener(self, __a0: ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener) -> None: ...

    def removeTool(self, __a0: ghidra.framework.plugintool.PluginTool) -> None: ...

    def restoreDefaultOptions(self) -> None: ...

    def scheduleOneTimeAnalysis(self, __a0: ghidra.app.services.Analyzer, __a1: ghidra.program.model.address.AddressSetView) -> None: ...

    def scheduleWorker(self, __a0: ghidra.app.plugin.core.analysis.AnalysisWorker, __a1: object, __a2: bool, __a3: ghidra.util.task.TaskMonitor) -> bool: ...

    def setDebug(self, __a0: bool) -> None: ...

    def setIgnoreChanges(self, __a0: bool) -> bool: ...

    def setProtectedLocation(self, __a0: ghidra.program.model.address.Address) -> None: ...

    def setProtectedLocations(self, __a0: ghidra.program.model.address.AddressSet) -> None: ...

    @overload
    def startAnalysis(self, __a0: ghidra.util.task.TaskMonitor) -> None: ...

    @overload
    def startAnalysis(self, __a0: ghidra.util.task.TaskMonitor, __a1: bool) -> None: ...

    def startBackgroundAnalysis(self) -> bool: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def waitForAnalysis(self, __a0: int, __a1: ghidra.util.task.TaskMonitor) -> None: ...

    @property
    def analysisTool(self) -> ghidra.framework.plugintool.PluginTool: ...

    @property
    def analyzing(self) -> bool: ...

    @property
    def dataTypeManagerService(self) -> ghidra.app.services.DataTypeManagerService: ...

    @property
    def debug(self) -> None: ...  # No getter available.

    @debug.setter
    def debug(self, value: bool) -> None: ...

    @property
    def ignoreChanges(self) -> None: ...  # No getter available.

    @ignoreChanges.setter
    def ignoreChanges(self, value: bool) -> None: ...

    @property
    def messageLog(self) -> ghidra.app.util.importer.MessageLog: ...

    @property
    def program(self) -> ghidra.program.model.listing.Program: ...

    @property
    def protectedLocation(self) -> None: ...  # No getter available.

    @protectedLocation.setter
    def protectedLocation(self, value: ghidra.program.model.address.Address) -> None: ...

    @property
    def protectedLocations(self) -> ghidra.program.model.address.AddressSetView: ...

    @property
    def taskTimesString(self) -> unicode: ...

    @property
    def timedTasks(self) -> List[unicode]: ...

    @property
    def totalTimeInMillis(self) -> int: ...