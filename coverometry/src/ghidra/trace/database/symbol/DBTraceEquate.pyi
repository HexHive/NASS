from typing import List
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.pcode
import ghidra.trace.model
import ghidra.trace.model.symbol
import ghidra.trace.model.thread
import ghidra.util
import ghidra.util.database
import java.lang
import java.util


class DBTraceEquate(ghidra.util.database.DBAnnotatedObject, ghidra.trace.model.symbol.TraceEquate):
    TABLE_NAME: unicode = u'Equates'



    def __init__(self, __a0: ghidra.trace.database.symbol.DBTraceEquateManager, __a1: ghidra.util.database.DBCachedObjectStore, __a2: db.DBRecord): ...



    @overload
    def addReference(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.trace.model.thread.TraceThread, __a2: ghidra.program.model.address.Address, __a3: int) -> ghidra.trace.model.symbol.TraceEquateReference: ...

    @overload
    def addReference(self, __a0: ghidra.trace.model.Lifespan, __a1: ghidra.trace.model.thread.TraceThread, __a2: ghidra.program.model.address.Address, __a3: ghidra.program.model.pcode.Varnode) -> ghidra.trace.model.symbol.TraceEquateReference: ...

    def delete(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDisplayName(self) -> unicode: ...

    def getDisplayValue(self) -> unicode: ...

    def getEnum(self) -> ghidra.program.model.data.Enum: ...

    def getKey(self) -> long: ...

    def getName(self) -> unicode: ...

    def getObjectKey(self) -> ghidra.util.database.ObjectKey: ...

    @overload
    def getReference(self, __a0: long, __a1: ghidra.trace.model.thread.TraceThread, __a2: ghidra.program.model.address.Address, __a3: int) -> ghidra.trace.model.symbol.TraceEquateReference: ...

    @overload
    def getReference(self, __a0: long, __a1: ghidra.trace.model.thread.TraceThread, __a2: ghidra.program.model.address.Address, __a3: ghidra.program.model.pcode.Varnode) -> ghidra.trace.model.symbol.TraceEquateReference: ...

    def getReferenceCount(self) -> int: ...

    @overload
    def getReferences(self) -> java.util.Collection: ...

    @overload
    def getReferences(self, __a0: ghidra.program.model.address.Address) -> List[object]: ...

    def getTableName(self) -> unicode: ...

    def getValue(self) -> long: ...

    def hasValidEnum(self) -> bool: ...

    def hashCode(self) -> int: ...

    @overload
    def isDeleted(self) -> bool: ...

    @overload
    def isDeleted(self, __a0: ghidra.util.Lock) -> bool: ...

    def isEnumBased(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setInvalid(self) -> None: ...

    def setName(self, __a0: unicode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def displayName(self) -> unicode: ...

    @property
    def displayValue(self) -> unicode: ...

    @property
    def enum(self) -> ghidra.program.model.data.Enum: ...

    @property
    def enumBased(self) -> bool: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def referenceCount(self) -> int: ...

    @property
    def references(self) -> java.util.Collection: ...

    @property
    def value(self) -> long: ...