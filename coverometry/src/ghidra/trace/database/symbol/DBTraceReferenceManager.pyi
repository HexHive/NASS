import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.program.model.symbol
import ghidra.trace.database
import ghidra.trace.database.space
import ghidra.trace.database.symbol
import ghidra.trace.model
import ghidra.trace.model.stack
import ghidra.trace.model.symbol
import ghidra.trace.model.thread
import ghidra.trace.util
import java.io
import java.lang
import java.util
import java.util.concurrent.locks
import java.util.function


class DBTraceReferenceManager(ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager, ghidra.trace.model.symbol.TraceReferenceManager, ghidra.trace.database.space.DBTraceDelegatingManager):
    NAME: unicode = u'Reference'



    def __init__(self, __a0: db.DBHandle, __a1: ghidra.util.database.DBOpenMode, __a2: java.util.concurrent.locks.ReadWriteLock, __a3: ghidra.util.task.TaskMonitor, __a4: ghidra.program.model.lang.Language, __a5: ghidra.trace.database.DBTrace, __a6: ghidra.trace.database.thread.DBTraceThreadManager, __a7: ghidra.trace.database.address.DBTraceOverlaySpaceAdapter): ...



    def addMemoryReference(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.address.Address, __a3: ghidra.program.model.symbol.RefType, __a4: ghidra.program.model.symbol.SourceType, __a5: int) -> ghidra.trace.database.symbol.DBTraceReference: ...

    def addOffsetReference(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.address.Address, __a3: bool, __a4: long, __a5: ghidra.program.model.symbol.RefType, __a6: ghidra.program.model.symbol.SourceType, __a7: int) -> ghidra.trace.database.symbol.DBTraceOffsetReference: ...

    @overload
    def addReference(self, __a0: ghidra.trace.model.symbol.TraceReference) -> ghidra.trace.model.symbol.TraceReference: ...

    @overload
    def addReference(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.symbol.Reference) -> ghidra.trace.database.symbol.DBTraceReference: ...

    def addRegisterReference(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.lang.Register, __a3: ghidra.program.model.symbol.RefType, __a4: ghidra.program.model.symbol.SourceType, __a5: int) -> ghidra.trace.model.symbol.TraceReference: ...

    def addShiftedReference(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.address.Address, __a3: int, __a4: ghidra.program.model.symbol.RefType, __a5: ghidra.program.model.symbol.SourceType, __a6: int) -> ghidra.trace.database.symbol.DBTraceShiftedReference: ...

    def addStackReference(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.Address, __a2: int, __a3: ghidra.program.model.symbol.RefType, __a4: ghidra.program.model.symbol.SourceType, __a5: int) -> ghidra.trace.database.symbol.DBTraceReference: ...

    def assertIsMine(self, __a0: ghidra.program.model.symbol.Reference) -> ghidra.trace.database.symbol.DBTraceReference: ...

    def checkIsInMemory(self, __a0: ghidra.program.model.address.AddressSpace) -> None: ...

    def clearReferencesFrom(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.AddressRange) -> None: ...

    def clearReferencesTo(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.AddressRange) -> None: ...

    def dbError(self, __a0: java.io.IOException) -> None: ...

    def delegateAddressSet(self, __a0: java.lang.Iterable, __a1: ghidra.trace.database.space.DBTraceDelegatingManager.ExcFunction) -> ghidra.program.model.address.AddressSetView: ...

    def delegateAny(self, __a0: java.lang.Iterable, __a1: ghidra.trace.database.space.DBTraceDelegatingManager.ExcPredicate) -> bool: ...

    def delegateCollection(self, __a0: java.lang.Iterable, __a1: java.util.function.Function) -> java.util.Collection: ...

    def delegateDeleteB(self, __a0: ghidra.program.model.address.AddressSpace, __a1: java.util.function.Predicate, __a2: bool) -> bool: ...

    def delegateDeleteV(self, __a0: ghidra.program.model.address.AddressSpace, __a1: ghidra.trace.database.space.DBTraceDelegatingManager.ExcConsumer) -> None: ...

    def delegateFirst(self, __a0: java.lang.Iterable, __a1: java.util.function.Function) -> object: ...

    def delegateHashSet(self, __a0: java.lang.Iterable, __a1: java.util.function.Function) -> java.util.HashSet: ...

    @overload
    def delegateRead(self, __a0: ghidra.program.model.address.AddressSpace, __a1: ghidra.trace.database.space.DBTraceDelegatingManager.ExcFunction) -> object: ...

    @overload
    def delegateRead(self, __a0: ghidra.program.model.address.AddressSpace, __a1: ghidra.trace.database.space.DBTraceDelegatingManager.ExcFunction, __a2: object) -> object: ...

    def delegateReadB(self, __a0: ghidra.program.model.address.AddressSpace, __a1: java.util.function.Predicate, __a2: bool) -> bool: ...

    @overload
    def delegateReadI(self, __a0: ghidra.program.model.address.AddressSpace, __a1: java.util.function.ToIntFunction, __a2: int) -> int: ...

    @overload
    def delegateReadI(self, __a0: ghidra.program.model.address.AddressSpace, __a1: java.util.function.ToIntFunction, __a2: java.util.function.IntSupplier) -> int: ...

    def delegateReadOr(self, __a0: ghidra.program.model.address.AddressSpace, __a1: ghidra.trace.database.space.DBTraceDelegatingManager.ExcFunction, __a2: ghidra.trace.database.space.DBTraceDelegatingManager.ExcSupplier) -> object: ...

    def delegateWrite(self, __a0: ghidra.program.model.address.AddressSpace, __a1: ghidra.trace.database.space.DBTraceDelegatingManager.ExcFunction) -> object: ...

    def delegateWriteAll(self, __a0: java.lang.Iterable, __a1: ghidra.trace.database.space.DBTraceDelegatingManager.ExcConsumer) -> None: ...

    def delegateWriteI(self, __a0: ghidra.program.model.address.AddressSpace, __a1: java.util.function.ToIntFunction) -> int: ...

    def delegateWriteV(self, __a0: ghidra.program.model.address.AddressSpace, __a1: ghidra.trace.database.space.DBTraceDelegatingManager.ExcConsumer) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, __a0: ghidra.trace.util.TraceAddressSpace, __a1: bool) -> ghidra.trace.database.space.DBTraceSpaceBased: ...

    def getActiveMemorySpaces(self) -> java.util.Collection: ...

    def getActiveRegisterSpaces(self) -> java.util.Collection: ...

    def getActiveSpaces(self) -> java.util.Collection: ...

    def getBaseLanguage(self) -> ghidra.program.model.lang.Language: ...

    def getClass(self) -> java.lang.Class: ...

    def getFlowReferencesFrom(self, __a0: long, __a1: ghidra.program.model.address.Address) -> java.util.Collection: ...

    def getForSpace(self, __a0: ghidra.program.model.address.AddressSpace, __a1: bool) -> ghidra.trace.database.space.DBTraceSpaceBased: ...

    def getLock(self) -> java.util.concurrent.locks.ReadWriteLock: ...

    def getPrimaryReferenceFrom(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: int) -> ghidra.trace.database.symbol.DBTraceReference: ...

    def getReference(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.address.Address, __a3: int) -> ghidra.trace.database.symbol.DBTraceReference: ...

    def getReferenceCountFrom(self, __a0: long, __a1: ghidra.program.model.address.Address) -> int: ...

    def getReferenceCountTo(self, __a0: long, __a1: ghidra.program.model.address.Address) -> int: ...

    def getReferenceDestinations(self, __a0: ghidra.trace.model.Lifespan) -> ghidra.program.model.address.AddressSetView: ...

    @overload
    def getReferenceRegisterSpace(self, __a0: ghidra.trace.model.stack.TraceStackFrame, __a1: bool) -> ghidra.trace.database.symbol.DBTraceReferenceSpace: ...

    @overload
    def getReferenceRegisterSpace(self, __a0: ghidra.trace.model.thread.TraceThread, __a1: bool) -> ghidra.trace.model.symbol.TraceReferenceSpace: ...

    def getReferenceSources(self, __a0: ghidra.trace.model.Lifespan) -> ghidra.program.model.address.AddressSetView: ...

    def getReferenceSpace(self, __a0: ghidra.program.model.address.AddressSpace, __a1: bool) -> ghidra.trace.model.symbol.TraceReferenceSpace: ...

    @overload
    def getReferencesFrom(self, __a0: long, __a1: ghidra.program.model.address.Address) -> java.util.Collection: ...

    @overload
    def getReferencesFrom(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: int) -> java.util.Collection: ...

    def getReferencesFromRange(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.AddressRange) -> java.util.Collection: ...

    def getReferencesTo(self, __a0: long, __a1: ghidra.program.model.address.Address) -> java.util.Collection: ...

    def getReferencesToRange(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.program.model.address.AddressRange) -> java.util.Collection: ...

    def getTrace(self) -> ghidra.trace.database.DBTrace: ...

    def hasFlowReferencesFrom(self, __a0: long, __a1: ghidra.program.model.address.Address) -> bool: ...

    @overload
    def hasReferencesFrom(self, __a0: long, __a1: ghidra.program.model.address.Address) -> bool: ...

    @overload
    def hasReferencesFrom(self, __a0: long, __a1: ghidra.program.model.address.Address, __a2: int) -> bool: ...

    def hasReferencesTo(self, __a0: long, __a1: ghidra.program.model.address.Address) -> bool: ...

    def hashCode(self) -> int: ...

    def invalidateCache(self, __a0: bool) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def readLock(self) -> java.util.concurrent.locks.Lock: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeLock(self) -> java.util.concurrent.locks.Lock: ...

