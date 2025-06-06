import ghidra.app.plugin.core.debug.service.emulation.data
import ghidra.pcode.emu
import ghidra.pcode.exec.trace.data
import ghidra.program.model.lang
import ghidra.trace.model.thread
import java.lang


class PcodeDebuggerAccess(ghidra.pcode.exec.trace.data.PcodeTraceAccess, object):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getDataForLocalState(self, __a0: ghidra.pcode.emu.PcodeThread, __a1: int) -> ghidra.pcode.exec.trace.data.PcodeTraceRegistersAccess: ...

    @overload
    def getDataForLocalState(self, __a0: ghidra.trace.model.thread.TraceThread, __a1: int) -> ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerRegistersAccess: ...

    def getDataForSharedState(self) -> ghidra.pcode.exec.trace.data.PcodeTraceMemoryAccess: ...

    def getDataForThreadState(self, __a0: ghidra.trace.model.thread.TraceThread, __a1: int) -> ghidra.pcode.exec.trace.data.PcodeTraceDataAccess: ...

    def getLanguage(self) -> ghidra.program.model.lang.Language: ...

    def hashCode(self) -> int: ...

    def newPcodeTraceThreadAccess(self, __a0: ghidra.pcode.exec.trace.data.PcodeTraceMemoryAccess, __a1: ghidra.pcode.exec.trace.data.PcodeTraceRegistersAccess) -> ghidra.pcode.exec.trace.data.PcodeTraceDataAccess: ...

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
    def dataForSharedState(self) -> ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerMemoryAccess: ...

    @property
    def language(self) -> ghidra.program.model.lang.Language: ...