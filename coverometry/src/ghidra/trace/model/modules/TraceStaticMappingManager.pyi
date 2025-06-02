import ghidra.program.model.address
import ghidra.trace.model
import ghidra.trace.model.modules
import java.lang
import java.net
import java.util


class TraceStaticMappingManager(object):








    def add(self, __a0: ghidra.program.model.address.AddressRange, __a1: ghidra.trace.model.Lifespan, __a2: java.net.URL, __a3: unicode) -> ghidra.trace.model.modules.TraceStaticMapping: ...

    def equals(self, __a0: object) -> bool: ...

    def findAllOverlapping(self, __a0: ghidra.program.model.address.AddressRange, __a1: ghidra.trace.model.Lifespan) -> java.util.Collection: ...

    def findAnyConflicting(self, __a0: ghidra.program.model.address.AddressRange, __a1: ghidra.trace.model.Lifespan, __a2: java.net.URL, __a3: unicode) -> ghidra.trace.model.modules.TraceStaticMapping: ...

    def findContaining(self, __a0: ghidra.program.model.address.Address, __a1: long) -> ghidra.trace.model.modules.TraceStaticMapping: ...

    def getAllEntries(self) -> java.util.Collection: ...

    def getClass(self) -> java.lang.Class: ...

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
    def allEntries(self) -> java.util.Collection: ...