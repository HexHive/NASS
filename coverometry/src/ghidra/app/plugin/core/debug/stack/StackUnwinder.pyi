import ghidra.app.plugin.core.debug
import ghidra.app.plugin.core.debug.stack
import ghidra.pcode.exec
import ghidra.program.model.address
import ghidra.util.task
import java.lang


class StackUnwinder(object):
    BASE_OP_INDEX: int = 0
    FRAMES_PATH: ghidra.program.model.data.CategoryPath = /Frames
    PC_OP_INDEX: int = -1



    def __init__(self, __a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.trace.model.guest.TracePlatform): ...



    def computeUnwindInfo(self, __a0: long, __a1: int, __a2: ghidra.program.model.address.Address, __a3: ghidra.util.task.TaskMonitor) -> ghidra.app.plugin.core.debug.stack.StackUnwinder.StaticAndUnwind: ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def frames(self, __a0: ghidra.app.plugin.core.debug.DebuggerCoordinates, __a1: ghidra.util.task.TaskMonitor) -> java.lang.Iterable: ...

    @overload
    def frames(self, __a0: ghidra.app.plugin.core.debug.DebuggerCoordinates, __a1: ghidra.pcode.exec.PcodeExecutorState, __a2: ghidra.util.task.TaskMonitor) -> java.lang.Iterable: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def start(self, __a0: ghidra.app.plugin.core.debug.DebuggerCoordinates, __a1: ghidra.util.task.TaskMonitor) -> ghidra.app.plugin.core.debug.stack.AnalysisUnwoundFrame: ...

    @overload
    def start(self, __a0: ghidra.app.plugin.core.debug.DebuggerCoordinates, __a1: ghidra.pcode.exec.PcodeExecutorState, __a2: ghidra.util.task.TaskMonitor) -> ghidra.app.plugin.core.debug.stack.AnalysisUnwoundFrame: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

