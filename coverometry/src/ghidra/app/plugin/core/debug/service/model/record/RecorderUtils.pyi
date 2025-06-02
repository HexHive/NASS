from typing import List
import ghidra.app.plugin.core.debug.service.model.record
import ghidra.app.services
import ghidra.program.model.address
import ghidra.util.task
import java.lang
import java.util
import java.util.concurrent


class RecorderUtils(java.lang.Enum):
    INSTANCE: ghidra.app.plugin.core.debug.service.model.record.RecorderUtils = INSTANCE







    @overload
    def compareTo(self, __a0: java.lang.Enum) -> int: ...

    @overload
    def compareTo(self, __a0: object) -> int: ...

    def describeConstable(self) -> java.util.Optional: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDeclaringClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def name(self) -> unicode: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def ordinal(self) -> int: ...

    def quantize(self, __a0: int, __a1: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSetView: ...

    def readMemoryBlocks(self, __a0: ghidra.app.services.TraceRecorder, __a1: int, __a2: ghidra.program.model.address.AddressSetView, __a3: ghidra.util.task.TaskMonitor) -> java.util.concurrent.CompletableFuture: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.app.plugin.core.debug.service.model.record.RecorderUtils: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.app.plugin.core.debug.service.model.record.RecorderUtils]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

