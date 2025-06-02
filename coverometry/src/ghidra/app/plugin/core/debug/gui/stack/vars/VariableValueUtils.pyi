from typing import List
import ghidra.app.decompiler
import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.gui.stack.vars
import ghidra.app.plugin.core.debug.stack
import ghidra.docking.settings
import ghidra.framework.plugintool
import ghidra.pcode.exec
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.trace.model.thread
import ghidra.util.task
import java.lang
import java.util


class VariableValueUtils(java.lang.Enum):





    class VariableEvaluator(object):




        def __init__(self, __a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.app.plugin.core.debug.DebuggerCoordinates): ...



        def dispose(self) -> None: ...

        def equals(self, __a0: object) -> bool: ...

        def getClass(self) -> java.lang.Class: ...

        def getGlobalsFakeFrame(self) -> ghidra.app.plugin.core.debug.stack.UnwoundFrame: ...

        def getRawRegisterValue(self, __a0: ghidra.program.model.lang.Register) -> ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue: ...

        def getRegisterUnit(self, __a0: ghidra.program.model.lang.Register) -> ghidra.trace.model.listing.TraceData: ...

        @overload
        def getRepresentation(self, __a0: ghidra.program.model.address.Address, __a1: List[int], __a2: ghidra.program.model.data.DataType, __a3: ghidra.docking.settings.Settings) -> unicode: ...

        @overload
        def getRepresentation(self, __a0: ghidra.app.plugin.core.debug.stack.UnwoundFrame, __a1: ghidra.program.model.address.Address, __a2: ghidra.pcode.exec.DebuggerPcodeUtils.WatchValue, __a3: ghidra.program.model.data.DataType) -> unicode: ...

        def getStackFrame(self, __a0: ghidra.program.model.listing.Function, __a1: ghidra.app.plugin.core.debug.stack.StackUnwindWarningSet, __a2: ghidra.util.task.TaskMonitor, __a3: bool) -> ghidra.app.plugin.core.debug.stack.UnwoundFrame: ...

        def hashCode(self) -> int: ...

        def invalidateCache(self) -> None: ...

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
        def globalsFakeFrame(self) -> ghidra.app.plugin.core.debug.stack.UnwoundFrame: ...





    @staticmethod
    def collectSymbolStorage(__a0: ghidra.app.decompiler.ClangLine) -> ghidra.program.model.address.AddressSet: ...

    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    @staticmethod
    def computeFrameSearchRange(__a0: ghidra.app.plugin.core.debug.DebuggerCoordinates) -> ghidra.program.model.address.AddressRange: ...

    @staticmethod
    def containsVarnode(__a0: ghidra.program.model.address.AddressSetView, __a1: ghidra.program.model.pcode.Varnode) -> bool: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def fabricateStorage(__a0: ghidra.program.model.pcode.HighVariable) -> ghidra.program.model.listing.VariableStorage: ...

    @staticmethod
    def findDeref(__a0: ghidra.program.model.address.AddressFactory, __a1: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.pcode.PcodeOp: ...

    @staticmethod
    def findStackVariable(__a0: ghidra.program.model.listing.Function, __a1: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Variable: ...

    @staticmethod
    def findVariable(__a0: ghidra.program.model.listing.Function, __a1: ghidra.program.model.lang.Register) -> ghidra.program.model.listing.Variable: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    @staticmethod
    def getInstanceInSymbolStorage(__a0: ghidra.program.model.pcode.HighVariable) -> ghidra.program.model.pcode.Varnode: ...

    @staticmethod
    def getProgramCounter(__a0: ghidra.trace.model.guest.TracePlatform, __a1: ghidra.trace.model.thread.TraceThread, __a2: long) -> ghidra.program.model.address.Address: ...

    @staticmethod
    def getProgramCounterFromRegisters(__a0: ghidra.trace.model.guest.TracePlatform, __a1: ghidra.trace.model.thread.TraceThread, __a2: long) -> ghidra.program.model.address.Address: ...

    @staticmethod
    def getProgramCounterFromStack(__a0: ghidra.trace.model.guest.TracePlatform, __a1: ghidra.trace.model.thread.TraceThread, __a2: long) -> ghidra.program.model.address.Address: ...

    @staticmethod
    def hasFreshUnwind(__a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.app.plugin.core.debug.DebuggerCoordinates) -> bool: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def locateFrame(__a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.app.plugin.core.debug.DebuggerCoordinates, __a2: ghidra.program.model.listing.Function) -> ghidra.app.plugin.core.debug.stack.ListingUnwoundFrame: ...

    @staticmethod
    def locateInnermost(__a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.app.plugin.core.debug.DebuggerCoordinates) -> ghidra.app.plugin.core.debug.stack.ListingUnwoundFrame: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    @staticmethod
    def rangeFromVarnode(__a0: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.address.AddressRange: ...

    @overload
    @staticmethod
    def requiresFrame(__a0: ghidra.program.model.pcode.PcodeOp, __a1: ghidra.program.model.address.AddressSetView) -> bool: ...

    @overload
    @staticmethod
    def requiresFrame(__a0: ghidra.program.model.listing.Program, __a1: ghidra.program.model.listing.VariableStorage, __a2: ghidra.program.model.address.AddressSetView) -> bool: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueUtils: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueUtils]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

