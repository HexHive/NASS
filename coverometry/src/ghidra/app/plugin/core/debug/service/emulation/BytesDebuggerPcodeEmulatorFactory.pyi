import ghidra.app.plugin.core.debug.service.emulation
import ghidra.app.plugin.core.debug.service.emulation.data
import ghidra.app.services
import ghidra.framework.plugintool
import ghidra.trace.model.guest
import java.lang


class BytesDebuggerPcodeEmulatorFactory(object, ghidra.app.plugin.core.debug.service.emulation.DebuggerPcodeEmulatorFactory):




    def __init__(self): ...



    @overload
    def create(self, __a0: ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerAccess) -> ghidra.app.plugin.core.debug.service.emulation.DebuggerPcodeMachine: ...

    @overload
    def create(self, __a0: ghidra.framework.plugintool.PluginTool, __a1: ghidra.trace.model.guest.TracePlatform, __a2: long, __a3: ghidra.app.services.TraceRecorder) -> ghidra.app.plugin.core.debug.service.emulation.DebuggerPcodeMachine: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getTitle(self) -> unicode: ...

    def hashCode(self) -> int: ...

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
    def title(self) -> unicode: ...