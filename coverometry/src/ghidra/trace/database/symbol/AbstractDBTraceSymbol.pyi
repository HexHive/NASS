from typing import List
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.trace.database.address
import ghidra.trace.model
import ghidra.trace.model.symbol
import ghidra.trace.model.thread
import ghidra.util
import ghidra.util.database
import ghidra.util.task
import java.lang
import java.util


class AbstractDBTraceSymbol(ghidra.util.database.DBAnnotatedObject, ghidra.trace.model.symbol.TraceSymbol, ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses):




    def __init__(self, __a0: ghidra.trace.database.symbol.DBTraceSymbolManager, __a1: ghidra.util.database.DBCachedObjectStore, __a2: db.DBRecord): ...



    def delete(self) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address: ...

    def getAddressSet(self) -> ghidra.program.model.address.AddressSet: ...

    def getClass(self) -> java.lang.Class: ...

    def getID(self) -> long: ...

    def getKey(self) -> long: ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan: ...

    @overload
    def getName(self) -> unicode: ...

    @overload
    def getName(self, __a0: bool) -> unicode: ...

    def getObject(self) -> object: ...

    def getObjectKey(self) -> ghidra.util.database.ObjectKey: ...

    def getOverlaySpaceAdapter(self) -> ghidra.trace.database.address.DBTraceOverlaySpaceAdapter: ...

    def getParentNamespace(self) -> ghidra.program.model.symbol.Namespace: ...

    def getParentSymbol(self) -> ghidra.program.model.symbol.Symbol: ...

    def getPath(self) -> List[unicode]: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation: ...

    def getReferenceCollection(self) -> java.util.Collection: ...

    def getReferenceCount(self) -> int: ...

    @overload
    def getReferences(self) -> List[ghidra.program.model.symbol.Reference]: ...

    @overload
    def getReferences(self, __a0: ghidra.util.task.TaskMonitor) -> List[ghidra.program.model.symbol.Reference]: ...

    def getSource(self) -> ghidra.program.model.symbol.SourceType: ...

    def getSymbolType(self) -> ghidra.program.model.symbol.SymbolType: ...

    def getTableName(self) -> unicode: ...

    def getThread(self) -> ghidra.trace.model.thread.TraceThread: ...

    def getTrace(self) -> ghidra.trace.model.Trace: ...

    def hasMultipleReferences(self) -> bool: ...

    def hasReferences(self) -> bool: ...

    def hashCode(self) -> int: ...

    @overload
    def isDeleted(self) -> bool: ...

    @overload
    def isDeleted(self, __a0: ghidra.util.Lock) -> bool: ...

    def isDescendant(self, __a0: ghidra.program.model.symbol.Namespace) -> bool: ...

    def isDynamic(self) -> bool: ...

    def isExternal(self) -> bool: ...

    def isExternalEntryPoint(self) -> bool: ...

    def isGlobal(self) -> bool: ...

    def isPinned(self) -> bool: ...

    def isPrimary(self) -> bool: ...

    def isValidParent(self, __a0: ghidra.program.model.symbol.Namespace) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setInvalid(self) -> None: ...

    def setName(self, __a0: unicode, __a1: ghidra.program.model.symbol.SourceType) -> None: ...

    def setNameAndNamespace(self, __a0: unicode, __a1: ghidra.program.model.symbol.Namespace, __a2: ghidra.program.model.symbol.SourceType) -> None: ...

    def setNamespace(self, __a0: ghidra.program.model.symbol.Namespace) -> None: ...

    def setPinned(self, __a0: bool) -> None: ...

    def setPrimary(self) -> bool: ...

    def setSource(self, __a0: ghidra.program.model.symbol.SourceType) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def ID(self) -> long: ...

    @property
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSet: ...

    @property
    def dynamic(self) -> bool: ...

    @property
    def external(self) -> bool: ...

    @property
    def externalEntryPoint(self) -> bool: ...

    @property
    def global(self) -> bool: ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan: ...

    @property
    def name(self) -> unicode: ...

    @property
    def namespace(self) -> None: ...  # No getter available.

    @namespace.setter
    def namespace(self, value: ghidra.program.model.symbol.Namespace) -> None: ...

    @property
    def overlaySpaceAdapter(self) -> ghidra.trace.database.address.DBTraceOverlaySpaceAdapter: ...

    @property
    def parentNamespace(self) -> ghidra.trace.database.symbol.DBTraceNamespaceSymbol: ...

    @property
    def parentSymbol(self) -> ghidra.trace.database.symbol.DBTraceNamespaceSymbol: ...

    @property
    def path(self) -> List[unicode]: ...

    @property
    def pinned(self) -> bool: ...

    @pinned.setter
    def pinned(self, value: bool) -> None: ...

    @property
    def program(self) -> ghidra.trace.database.program.DBTraceProgramView: ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation: ...

    @property
    def referenceCollection(self) -> java.util.Collection: ...

    @property
    def referenceCount(self) -> int: ...

    @property
    def references(self) -> List[ghidra.trace.database.symbol.DBTraceReference]: ...

    @property
    def source(self) -> ghidra.program.model.symbol.SourceType: ...

    @source.setter
    def source(self, value: ghidra.program.model.symbol.SourceType) -> None: ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread: ...

    @property
    def trace(self) -> ghidra.trace.database.DBTrace: ...