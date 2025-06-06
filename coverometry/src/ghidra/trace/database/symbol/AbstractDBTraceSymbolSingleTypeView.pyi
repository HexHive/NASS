import ghidra.trace.database.symbol
import ghidra.trace.model.symbol
import java.lang
import java.util


class AbstractDBTraceSymbolSingleTypeView(object):




    def __init__(self, __a0: ghidra.trace.database.symbol.DBTraceSymbolManager, __a1: int, __a2: ghidra.util.database.DBCachedObjectStore): ...



    def equals(self, __a0: object) -> bool: ...

    def getAll(self, __a0: bool) -> java.util.Collection: ...

    def getByKey(self, __a0: long) -> ghidra.trace.database.symbol.AbstractDBTraceSymbol: ...

    def getChildren(self, __a0: ghidra.trace.model.symbol.TraceNamespaceSymbol) -> java.util.Collection: ...

    def getChildrenNamed(self, __a0: unicode, __a1: ghidra.trace.model.symbol.TraceNamespaceSymbol) -> java.util.Collection: ...

    def getClass(self) -> java.lang.Class: ...

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

    @property
    def manager(self) -> ghidra.trace.database.symbol.DBTraceSymbolManager: ...