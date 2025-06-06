from typing import List
import ghidra.program.database.function
import ghidra.program.database.symbol
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util
import ghidra.util.task
import java.lang


class GlobalVariableSymbolDB(ghidra.program.database.symbol.VariableSymbolDB):




    def __init__(self, symbolMgr: ghidra.program.database.symbol.SymbolManager, cache: ghidra.program.database.DBObjectCache, variableMgr: ghidra.program.database.symbol.VariableStorageManagerDB, address: ghidra.program.model.address.Address, record: db.DBRecord):
        """
        Constructs a new GlobalVariableSymbolDB which are restricted to the global namespace
        @param symbolMgr the symbol manager
        @param cache symbol object cache
        @param variableMgr variable storage manager
        @param address the address of the symbol (stack address)
        @param record the record for the symbol
        """
        ...



    def delete(self) -> bool:
        """
        @see ghidra.program.model.symbol.Symbol#delete()
        """
        ...

    def doSetNameAndNamespace(self, newName: unicode, newNamespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType, checkForDuplicates: bool) -> None: ...

    def equals(self, obj: object) -> bool:
        """
        @see ghidra.program.database.symbol.SymbolDB#equals(java.lang.Object)
        """
        ...

    def getAddress(self) -> ghidra.program.model.address.Address: ...

    def getClass(self) -> java.lang.Class: ...

    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    def getDataTypeId(self) -> long: ...

    def getFirstUseOffset(self) -> int: ...

    def getFunction(self) -> ghidra.program.database.function.FunctionDB: ...

    def getID(self) -> long: ...

    def getKey(self) -> long:
        """
        Get the database key for this object.
        """
        ...

    @overload
    def getName(self) -> unicode: ...

    @overload
    def getName(self, includeNamespace: bool) -> unicode: ...

    def getObject(self) -> object: ...

    def getOrdinal(self) -> int: ...

    def getParentNamespace(self) -> ghidra.program.model.symbol.Namespace: ...

    def getParentSymbol(self) -> ghidra.program.model.symbol.Symbol: ...

    def getPath(self) -> List[unicode]: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        @see ghidra.program.model.symbol.Symbol#getProgramLocation()
        """
        ...

    def getReferenceCount(self) -> int: ...

    @overload
    def getReferences(self) -> List[ghidra.program.model.symbol.Reference]: ...

    @overload
    def getReferences(self, monitor: ghidra.util.task.TaskMonitor) -> List[ghidra.program.model.symbol.Reference]: ...

    def getSource(self) -> ghidra.program.model.symbol.SourceType: ...

    def getSymbolStringData(self) -> unicode:
        """
        Returns the symbol's string data which has different meanings depending on the symbol type
         and whether or not it is external
        @return the symbol's string data
        """
        ...

    def getSymbolType(self) -> ghidra.program.model.symbol.SymbolType: ...

    def getVariableStorage(self) -> ghidra.program.model.listing.VariableStorage: ...

    def hasMultipleReferences(self) -> bool: ...

    def hasReferences(self) -> bool: ...

    def hashCode(self) -> int: ...

    @overload
    def isDeleted(self) -> bool: ...

    @overload
    def isDeleted(self, lock: ghidra.util.Lock) -> bool:
        """
        Returns true if this object has been deleted. Note: once an object has been deleted, it will
         never be "refreshed". For example, if an object is ever deleted and is resurrected via an
         "undo", you will have get a fresh instance of the object.
        @param lock object cache lock object
        @return true if this object has been deleted.
        """
        ...

    def isDeleting(self) -> bool: ...

    def isDescendant(self, namespace: ghidra.program.model.symbol.Namespace) -> bool: ...

    def isDynamic(self) -> bool: ...

    def isExternal(self) -> bool: ...

    def isExternalEntryPoint(self) -> bool: ...

    def isGlobal(self) -> bool: ...

    def isPinned(self) -> bool: ...

    def isPrimary(self) -> bool:
        """
        @see ghidra.program.model.symbol.Symbol#isPrimary()
        """
        ...

    def isValidParent(self, parent: ghidra.program.model.symbol.Namespace) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setDataTypeId(self, value: long) -> None:
        """
        Sets the generic symbol data 1.
        @param value the value to set as symbol data 1.
        """
        ...

    def setFirstUseOffset(self, firstUseOffset: int) -> None: ...

    def setInvalid(self) -> None: ...

    def setName(self, newName: unicode, source: ghidra.program.model.symbol.SourceType) -> None: ...

    def setNameAndNamespace(self, newName: unicode, newNamespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType) -> None: ...

    def setNamespace(self, newNamespace: ghidra.program.model.symbol.Namespace) -> None: ...

    def setOrdinal(self, ordinal: int) -> None: ...

    def setPinned(self, pinned: bool) -> None: ...

    def setPrimary(self) -> bool:
        """
        @see ghidra.program.model.symbol.Symbol#setPrimary()
        """
        ...

    def setSource(self, newSource: ghidra.program.model.symbol.SourceType) -> None:
        """
        Sets this symbol's source as specified.
        @param newSource the new source type (IMPORTED, ANALYSIS, USER_DEFINED)
        @throws IllegalArgumentException if you try to change the source from default or to default
        """
        ...

    def setStorageAndDataType(self, newStorage: ghidra.program.model.listing.VariableStorage, dt: ghidra.program.model.data.DataType) -> None:
        """
        Change the storage address and data-type associated with this
         variable symbol.
        @param newStorage
        @param dt data-type
        """
        ...

    def setSymbolStringData(self, stringData: unicode) -> None:
        """
        Sets the symbol's string data field. This field's data has different uses depending on the 
         symbol type and whether or not it is external.
        @param stringData the string to store in the string data field
        """
        ...

    def setVariableOffset(self, offset: int) -> None:
        """
        Sets the symbol's variable offset. For parameters, this is the ordinal, for locals, it is 
         the first use offset
        @param offset the value to set as the symbols variable offset.
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
    def object(self) -> object: ...

    @property
    def symbolType(self) -> ghidra.program.model.symbol.SymbolType: ...