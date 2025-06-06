import ghidra.program.model.address
import ghidra.trace.database.symbol
import ghidra.trace.model
import ghidra.trace.model.symbol
import ghidra.trace.model.thread
import java.lang
import java.util


class AbstractDBTraceSymbolSingleTypeWithLocationView(ghidra.trace.database.symbol.AbstractDBTraceSymbolSingleTypeView):




    def __init__(self, __a0: ghidra.trace.database.symbol.DBTraceSymbolManager, __a1: int, __a2: ghidra.util.database.DBCachedObjectStore): ...



    def equals(self, __a0: object) -> bool: ...

    def getAll(self, __a0: bool) -> java.util.Collection: ...

    def getAt(self, __a0: long, __a1: ghidra.trace.model.thread.TraceThread, __a2: ghidra.program.model.address.Address, __a3: bool) -> java.util.Collection: ...

    def getByKey(self, __a0: long) -> ghidra.trace.database.symbol.AbstractDBTraceSymbol: ...

    def getChildWithNameAt(self, __a0: unicode, __a1: long, __a2: ghidra.trace.model.thread.TraceThread, __a3: ghidra.program.model.address.Address, __a4: ghidra.trace.model.symbol.TraceNamespaceSymbol) -> ghidra.trace.database.symbol.AbstractDBTraceSymbol: ...

    def getChildren(self, __a0: ghidra.trace.model.symbol.TraceNamespaceSymbol) -> java.util.Collection: ...

    def getChildrenNamed(self, __a0: unicode, __a1: ghidra.trace.model.symbol.TraceNamespaceSymbol) -> java.util.Collection: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getIntersecting(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.trace.model.thread.TraceThread, __a2: ghidra.program.model.address.AddressRange, __a3: bool) -> java.util.Collection: ...

    @overload
    def getIntersecting(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.trace.model.thread.TraceThread, __a2: ghidra.program.model.address.AddressRange, __a3: bool, __a4: bool) -> java.util.Collection: ...

    def getManager(self) -> ghidra.trace.database.symbol.DBTraceSymbolManager: ...

    def getNamed(self, __a0: unicode) -> java.util.Collection: ...

    def getWithMatchingName(self, __a0: unicode, __a1: bool) -> java.util.Collection: ...

    def hashCode(self) -> int: ...

    def invalidateCache(self) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def scanByName(self, __a0: unicode) -> java.util.Iterator: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

