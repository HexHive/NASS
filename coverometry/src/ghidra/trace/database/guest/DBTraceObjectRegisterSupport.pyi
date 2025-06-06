from typing import List
import ghidra.program.model.address
import ghidra.trace.database.guest
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.symbol
import ghidra.trace.model.target
import ghidra.trace.util
import java.lang
import java.util


class DBTraceObjectRegisterSupport(java.lang.Enum):
    INSTANCE: ghidra.trace.database.guest.DBTraceObjectRegisterSupport = INSTANCE







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

    def onMappingAddedCheckTransfer(self, __a0: ghidra.trace.model.guest.TraceGuestPlatformMappedRange) -> None: ...

    def onMappingAddedCheckTransferMemoryMapped(self, __a0: ghidra.trace.model.target.TraceObject, __a1: ghidra.trace.model.guest.TraceGuestPlatformMappedRange) -> None: ...

    def onSpaceAddedCheckTransfer(self, __a0: ghidra.trace.model.Trace, __a1: ghidra.program.model.address.AddressSpace) -> None: ...

    def onSymbolAddedCheckTransfer(self, __a0: ghidra.trace.model.symbol.TraceSymbol) -> None: ...

    def onSymbolAddedCheckTransferToLabel(self, __a0: ghidra.trace.model.symbol.TraceLabelSymbol, __a1: bool) -> None: ...

    def onValueCreatedCheckTransfer(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> None: ...

    def onValueCreatedTransfer(self, __a0: ghidra.trace.model.target.TraceObjectValue) -> None: ...

    def ordinal(self) -> int: ...

    def processEvent(self, __a0: ghidra.trace.util.TraceChangeRecord) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    @staticmethod
    def valueOf(__a0: unicode) -> ghidra.trace.database.guest.DBTraceObjectRegisterSupport: ...

    @overload
    @staticmethod
    def valueOf(__a0: java.lang.Class, __a1: unicode) -> java.lang.Enum: ...

    @staticmethod
    def values() -> List[ghidra.trace.database.guest.DBTraceObjectRegisterSupport]: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

