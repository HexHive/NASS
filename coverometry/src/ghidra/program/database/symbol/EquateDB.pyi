from typing import List
import ghidra.program.database
import ghidra.program.model.address
import ghidra.program.model.symbol
import ghidra.util
import java.lang


class EquateDB(ghidra.program.database.DatabaseObject, ghidra.program.model.symbol.Equate):
    """
    Database object for an Equate.
    """





    def __init__(self, equateMgr: ghidra.program.database.symbol.EquateManager, cache: ghidra.program.database.DBObjectCache, record: db.DBRecord):
        """
        Constructor
        @param equateMgr the equate manager
        @param cache EquateDB cache
        @param record the record for this equate.
        """
        ...



    @overload
    def addReference(self, refAddr: ghidra.program.model.address.Address, opIndex: int) -> None: ...

    @overload
    def addReference(self, dynamicHash: long, refAddr: ghidra.program.model.address.Address) -> None: ...

    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDisplayName(self) -> unicode: ...

    def getDisplayValue(self) -> unicode: ...

    def getEnumUUID(self) -> ghidra.util.UniversalID: ...

    def getKey(self) -> long:
        """
        Get the database key for this object.
        """
        ...

    def getName(self) -> unicode: ...

    def getReferenceCount(self) -> int: ...

    @overload
    def getReferences(self) -> List[ghidra.program.model.symbol.EquateReference]: ...

    @overload
    def getReferences(self, refAddr: ghidra.program.model.address.Address) -> List[ghidra.program.model.symbol.EquateReference]: ...

    def getValue(self) -> long: ...

    def hashCode(self) -> int: ...

    def isDeleted(self, lock: ghidra.util.Lock) -> bool:
        """
        Returns true if this object has been deleted. Note: once an object has been deleted, it will
         never be "refreshed". For example, if an object is ever deleted and is resurrected via an
         "undo", you will have get a fresh instance of the object.
        @param lock object cache lock object
        @return true if this object has been deleted.
        """
        ...

    def isEnumBased(self) -> bool: ...

    def isValidUUID(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @overload
    def removeReference(self, refAddr: ghidra.program.model.address.Address, opIndex: int) -> None: ...

    @overload
    def removeReference(self, dynamicHash: long, refAddr: ghidra.program.model.address.Address) -> None: ...

    def renameEquate(self, newName: unicode) -> None: ...

    def setInvalid(self) -> None:
        """
        Invalidate this object. This does not necessarily mean that this object can never be used
         again. If the object can refresh itself, it may still be useable.
        """
        ...

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
    def enumBased(self) -> bool: ...

    @property
    def enumUUID(self) -> ghidra.util.UniversalID: ...

    @property
    def name(self) -> unicode: ...

    @property
    def referenceCount(self) -> int: ...

    @property
    def references(self) -> List[ghidra.program.model.symbol.EquateReference]: ...

    @property
    def validUUID(self) -> bool: ...

    @property
    def value(self) -> long: ...