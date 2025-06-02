import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.symbol
import ghidra.util.task
import java.lang
import java.util


class TraceEquateOperations(object):








    @overload
    def clearReferences(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.AddressRange, __a2: ghidra.util.task.TaskMonitor) -> None: ...

    @overload
    def clearReferences(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.AddressSetView, __a2: ghidra.util.task.TaskMonitor) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getReferenced(self, __a0: long, __a1: ghidra.program.model.address.Address) -> java.util.Collection: ...

    @overload
    def getReferenced(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: int) -> java.util.Collection: ...

    def getReferencedByValue(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: int, __a3: long) -> ghidra.trace.model.symbol.TraceEquate: ...

    def getReferringAddresses(self, __a0: ghidra.trace.model.Lifespan) -> ghidra.program.model.address.AddressSetView: ...

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

