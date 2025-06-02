import ghidra.program.model.address
import ghidra.rmi.trace
import java.lang


class ValueDecoder(object):
    DEFAULT: ghidra.app.plugin.core.debug.service.rmi.trace.ValueDecoder = ghidra.app.plugin.core.debug.service.rmi.trace.ValueDecoder$1@60d3ee32







    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getObject(self, __a0: ghidra.rmi.trace.TraceRmi.ObjDesc, __a1: bool) -> object: ...

    @overload
    def getObject(self, __a0: ghidra.rmi.trace.TraceRmi.ObjSpec, __a1: bool) -> object: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toAddress(self, __a0: ghidra.rmi.trace.TraceRmi.Addr, __a1: bool) -> ghidra.program.model.address.Address: ...

    def toRange(self, __a0: ghidra.rmi.trace.TraceRmi.AddrRange, __a1: bool) -> ghidra.program.model.address.AddressRange: ...

    def toString(self) -> unicode: ...

    def toValue(self, __a0: ghidra.rmi.trace.TraceRmi.Value) -> object: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

