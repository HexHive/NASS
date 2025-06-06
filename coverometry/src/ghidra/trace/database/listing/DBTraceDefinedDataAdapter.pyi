from typing import List
import ghidra.docking.settings
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.scalar
import ghidra.program.model.symbol
import ghidra.trace.database.data
import ghidra.trace.database.listing
import ghidra.trace.database.symbol
import ghidra.trace.model
import ghidra.trace.model.guest
import ghidra.trace.model.listing
import ghidra.trace.model.symbol
import ghidra.trace.model.thread
import ghidra.trace.util
import ghidra.util
import java.io
import java.lang
import java.nio
import java.util


class DBTraceDefinedDataAdapter(ghidra.trace.database.listing.DBTraceDataAdapter, object):
    COMMENT_PROPERTY: unicode = u'COMMENT__GHIDRA_'
    DATA_OP_INDEX: int = 0
    DEFINED_DATA_PROPERTY: unicode = u'DEFINED_DATA__GHIDRA_'
    EMPTY_INT_ARRAY: List[int] = array('i')
    EMPTY_STRING_ARRAY: List[unicode] = array(java.lang.String)
    EOL_COMMENT: int = 0
    INSTRUCTION_PROPERTY: unicode = u'INSTRUCTION__GHIDRA_'
    MNEMONIC: int = -1
    NO_COMMENT: int = -1
    PLATE_COMMENT: int = 3
    POST_COMMENT: int = 2
    PRE_COMMENT: int = 1
    REPEATABLE_COMMENT: int = 4
    SPACE_PROPERTY: unicode = u'Space'







    def addMnemonicReference(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.symbol.RefType, __a2: ghidra.program.model.symbol.SourceType) -> None: ...

    def addOperandReference(self, __a0: int, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.symbol.RefType, __a3: ghidra.program.model.symbol.SourceType) -> None: ...

    def addValueReference(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.symbol.RefType) -> None: ...

    def clearAllSettings(self) -> None: ...

    def clearSetting(self, __a0: unicode) -> None: ...

    def compareTo(self, __a0: ghidra.program.model.address.Address) -> int: ...

    def contains(self, __a0: ghidra.program.model.address.Address) -> bool: ...

    def delete(self) -> None: ...

    def doGetComponent(self, __a0: List[int], __a1: int) -> ghidra.trace.database.listing.DBTraceDefinedDataAdapter: ...

    def doGetComponentCache(self) -> List[ghidra.trace.database.listing.AbstractDBTraceDataComponent]: ...

    def doToString(self) -> unicode: ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def getAddress(self) -> ghidra.program.model.address.Address: ...

    @overload
    def getAddress(self, __a0: int) -> ghidra.program.model.address.Address: ...

    def getAddressString(self, __a0: bool, __a1: bool) -> unicode: ...

    def getBaseDataType(self) -> ghidra.program.model.data.DataType: ...

    def getBigInteger(self, __a0: int, __a1: int, __a2: bool) -> long: ...

    def getBounds(self) -> ghidra.trace.model.TraceAddressSnapRange: ...

    def getByte(self, __a0: int) -> int: ...

    @overload
    def getBytes(self) -> List[int]: ...

    @overload
    def getBytes(self, __a0: List[int], __a1: int) -> int: ...

    @overload
    def getBytes(self, __a0: java.nio.ByteBuffer, __a1: int) -> int: ...

    def getBytesInCodeUnit(self, __a0: List[int], __a1: int) -> None: ...

    def getBytesInFull(self, __a0: int, __a1: int) -> java.nio.ByteBuffer: ...

    def getClass(self) -> java.lang.Class: ...

    def getComment(self, __a0: int) -> unicode: ...

    def getCommentAsArray(self, __a0: int) -> List[unicode]: ...

    @overload
    def getComponent(self, __a0: int) -> ghidra.program.model.listing.Data: ...

    @overload
    def getComponent(self, __a0: List[int]) -> ghidra.program.model.listing.Data: ...

    def getComponentAt(self, __a0: int) -> ghidra.program.model.listing.Data: ...

    def getComponentContaining(self, __a0: int) -> ghidra.trace.model.listing.TraceData: ...

    def getComponentIndex(self) -> int: ...

    def getComponentLevel(self) -> int: ...

    def getComponentPath(self) -> List[int]: ...

    def getComponentPathName(self) -> unicode: ...

    def getComponentsContaining(self, __a0: int) -> List[object]: ...

    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    def getDefaultLabelPrefix(self, __a0: ghidra.program.model.data.DataTypeDisplayOptions) -> unicode: ...

    def getDefaultSettings(self) -> ghidra.docking.settings.Settings: ...

    def getDefaultValueRepresentation(self) -> unicode: ...

    def getEndSnap(self) -> long: ...

    def getExternalReference(self, __a0: int) -> ghidra.program.model.symbol.ExternalReference: ...

    def getFieldName(self) -> unicode: ...

    @overload
    def getInputStream(self) -> java.io.InputStream: ...

    @overload
    def getInputStream(self, __a0: int, __a1: int) -> java.io.InputStream: ...

    def getInt(self, __a0: int) -> int: ...

    def getIntProperty(self, __a0: unicode) -> int: ...

    def getLabel(self) -> unicode: ...

    def getLanguage(self) -> ghidra.program.model.lang.Language: ...

    def getLength(self) -> int: ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan: ...

    @overload
    def getLong(self, __a0: int) -> long: ...

    @overload
    def getLong(self, __a0: unicode) -> long: ...

    def getMaxAddress(self) -> ghidra.program.model.address.Address: ...

    def getMemory(self) -> ghidra.program.model.mem.Memory: ...

    def getMinAddress(self) -> ghidra.program.model.address.Address: ...

    def getMnemonicReferences(self) -> List[ghidra.program.model.symbol.Reference]: ...

    def getMnemonicString(self) -> unicode: ...

    def getNames(self) -> List[unicode]: ...

    def getNumComponents(self) -> int: ...

    def getNumOperands(self) -> int: ...

    def getObjectProperty(self, __a0: unicode) -> ghidra.util.Saveable: ...

    def getOperandReferences(self, __a0: int) -> List[ghidra.trace.database.symbol.DBTraceReference]: ...

    def getParent(self) -> ghidra.program.model.listing.Data: ...

    def getParentOffset(self) -> int: ...

    @overload
    def getPathName(self) -> unicode: ...

    @overload
    def getPathName(self, __a0: java.lang.StringBuilder, __a1: bool) -> java.lang.StringBuilder: ...

    def getPlatform(self) -> ghidra.trace.model.guest.TracePlatform: ...

    def getPrimaryReference(self, __a0: int) -> ghidra.trace.model.symbol.TraceReference: ...

    def getPrimarySymbol(self) -> ghidra.program.model.symbol.Symbol: ...

    def getPrimarySymbolOrDynamicName(self) -> unicode: ...

    def getPrimitiveAt(self, __a0: int) -> ghidra.trace.model.listing.TraceData: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getProperty(self, __a0: unicode, __a1: java.lang.Class) -> object: ...

    def getRange(self) -> ghidra.program.model.address.AddressRange: ...

    def getReferenceIteratorTo(self) -> ghidra.program.model.symbol.ReferenceIterator: ...

    def getReferencesFrom(self) -> List[ghidra.program.model.symbol.Reference]: ...

    def getRoot(self) -> ghidra.program.model.listing.Data: ...

    def getRootOffset(self) -> int: ...

    def getScalar(self, __a0: int) -> ghidra.program.model.scalar.Scalar: ...

    def getSettingsDefinition(self, __a0: java.lang.Class) -> ghidra.docking.settings.SettingsDefinition: ...

    def getSettingsSpace(self, __a0: bool) -> ghidra.trace.database.data.DBTraceDataSettingsOperations: ...

    def getShort(self, __a0: int) -> int: ...

    def getStartSnap(self) -> long: ...

    def getString(self, __a0: unicode) -> unicode: ...

    def getStringProperty(self, __a0: unicode) -> unicode: ...

    def getSuggestedValues(self, __a0: ghidra.docking.settings.StringSettingsDefinition) -> List[unicode]: ...

    def getSymbols(self) -> List[ghidra.program.model.symbol.Symbol]: ...

    def getThread(self) -> ghidra.trace.model.thread.TraceThread: ...

    def getTrace(self) -> ghidra.trace.model.Trace: ...

    def getTraceSpace(self) -> ghidra.trace.util.TraceAddressSpace: ...

    def getUnsignedByte(self, __a0: int) -> int: ...

    def getUnsignedInt(self, __a0: int) -> long: ...

    def getUnsignedShort(self, __a0: int) -> int: ...

    @overload
    def getValue(self) -> object: ...

    @overload
    def getValue(self, __a0: unicode) -> object: ...

    def getValueClass(self) -> java.lang.Class: ...

    def getValueReferences(self) -> List[ghidra.program.model.symbol.Reference]: ...

    def getVarLengthInt(self, __a0: int, __a1: int) -> int: ...

    def getVarLengthUnsignedInt(self, __a0: int, __a1: int) -> long: ...

    def getVoidProperty(self, __a0: unicode) -> bool: ...

    def hasMutability(self, __a0: int) -> bool: ...

    def hasProperty(self, __a0: unicode) -> bool: ...

    def hasStringValue(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isArray(self) -> bool: ...

    def isBigEndian(self) -> bool: ...

    def isChangeAllowed(self, __a0: ghidra.docking.settings.SettingsDefinition) -> bool: ...

    def isConstant(self) -> bool: ...

    def isDefined(self) -> bool: ...

    def isDynamic(self) -> bool: ...

    def isEmpty(self) -> bool: ...

    def isInitializedMemory(self) -> bool: ...

    def isPointer(self) -> bool: ...

    def isStructure(self) -> bool: ...

    def isUnion(self) -> bool: ...

    def isVolatile(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def propertyNames(self) -> java.util.Iterator: ...

    def removeExternalReference(self, __a0: int) -> None: ...

    def removeMnemonicReference(self, __a0: ghidra.program.model.address.Address) -> None: ...

    def removeOperandReference(self, __a0: int, __a1: ghidra.program.model.address.Address) -> None: ...

    def removeProperty(self, __a0: unicode) -> None: ...

    def removeValueReference(self, __a0: ghidra.program.model.address.Address) -> None: ...

    def setComment(self, __a0: int, __a1: unicode) -> None: ...

    def setCommentAsArray(self, __a0: int, __a1: List[unicode]) -> None: ...

    def setEndSnap(self, __a0: long) -> None: ...

    def setLong(self, __a0: unicode, __a1: long) -> None: ...

    def setPrimaryMemoryReference(self, __a0: ghidra.program.model.symbol.Reference) -> None: ...

    @overload
    def setProperty(self, __a0: unicode) -> None: ...

    @overload
    def setProperty(self, __a0: unicode, __a1: int) -> None: ...

    @overload
    def setProperty(self, __a0: unicode, __a1: unicode) -> None: ...

    @overload
    def setProperty(self, __a0: unicode, __a1: ghidra.util.Saveable) -> None: ...

    @overload
    def setProperty(self, __a0: unicode, __a1: java.lang.Class, __a2: object) -> None: ...

    def setRegisterReference(self, __a0: int, __a1: ghidra.program.model.lang.Register, __a2: ghidra.program.model.symbol.SourceType, __a3: ghidra.program.model.symbol.RefType) -> None: ...

    def setStackReference(self, __a0: int, __a1: int, __a2: ghidra.program.model.symbol.SourceType, __a3: ghidra.program.model.symbol.RefType) -> None: ...

    def setString(self, __a0: unicode, __a1: unicode) -> None: ...

    def setTypedProperty(self, __a0: unicode, __a1: object) -> None: ...

    def setValue(self, __a0: unicode, __a1: object) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def address(self) -> ghidra.program.model.address.Address: ...

    @property
    def array(self) -> bool: ...

    @property
    def baseDataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def bigEndian(self) -> bool: ...

    @property
    def bounds(self) -> ghidra.trace.model.TraceAddressSnapRange: ...

    @property
    def bytes(self) -> List[int]: ...

    @property
    def componentIndex(self) -> int: ...

    @property
    def componentLevel(self) -> int: ...

    @property
    def componentPath(self) -> List[int]: ...

    @property
    def componentPathName(self) -> unicode: ...

    @property
    def constant(self) -> bool: ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def defaultSettings(self) -> ghidra.docking.settings.Settings: ...

    @property
    def defaultValueRepresentation(self) -> unicode: ...

    @property
    def defined(self) -> bool: ...

    @property
    def dynamic(self) -> bool: ...

    @property
    def empty(self) -> bool: ...

    @property
    def endSnap(self) -> long: ...

    @endSnap.setter
    def endSnap(self, value: long) -> None: ...

    @property
    def fieldName(self) -> unicode: ...

    @property
    def initializedMemory(self) -> bool: ...

    @property
    def inputStream(self) -> java.io.InputStream: ...

    @property
    def label(self) -> unicode: ...

    @property
    def language(self) -> ghidra.program.model.lang.Language: ...

    @property
    def length(self) -> int: ...

    @property
    def lifespan(self) -> ghidra.trace.model.Lifespan: ...

    @property
    def maxAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def memory(self) -> ghidra.program.model.mem.Memory: ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def mnemonicReferences(self) -> List[ghidra.trace.database.symbol.DBTraceReference]: ...

    @property
    def mnemonicString(self) -> unicode: ...

    @property
    def names(self) -> List[unicode]: ...

    @property
    def numComponents(self) -> int: ...

    @property
    def numOperands(self) -> int: ...

    @property
    def parent(self) -> ghidra.trace.database.listing.DBTraceDefinedDataAdapter: ...

    @property
    def parentOffset(self) -> int: ...

    @property
    def pathName(self) -> unicode: ...

    @property
    def platform(self) -> ghidra.trace.model.guest.TracePlatform: ...

    @property
    def pointer(self) -> bool: ...

    @property
    def primaryMemoryReference(self) -> None: ...  # No getter available.

    @primaryMemoryReference.setter
    def primaryMemoryReference(self, value: ghidra.program.model.symbol.Reference) -> None: ...

    @property
    def primarySymbol(self) -> ghidra.program.model.symbol.Symbol: ...

    @property
    def primarySymbolOrDynamicName(self) -> unicode: ...

    @property
    def program(self) -> ghidra.trace.model.program.TraceProgramView: ...

    @property
    def property(self) -> None: ...  # No getter available.

    @property.setter
    def property(self, value: unicode) -> None: ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange: ...

    @property
    def referenceIteratorTo(self) -> ghidra.program.model.symbol.ReferenceIterator: ...

    @property
    def referencesFrom(self) -> List[ghidra.trace.database.symbol.DBTraceReference]: ...

    @property
    def root(self) -> ghidra.trace.database.listing.DBTraceData: ...

    @property
    def rootOffset(self) -> int: ...

    @property
    def startSnap(self) -> long: ...

    @property
    def structure(self) -> bool: ...

    @property
    def symbols(self) -> List[ghidra.program.model.symbol.Symbol]: ...

    @property
    def thread(self) -> ghidra.trace.model.thread.TraceThread: ...

    @property
    def trace(self) -> ghidra.trace.database.DBTrace: ...

    @property
    def traceSpace(self) -> ghidra.trace.util.TraceAddressSpace: ...

    @property
    def union(self) -> bool: ...

    @property
    def value(self) -> object: ...

    @property
    def valueClass(self) -> java.lang.Class: ...

    @property
    def valueReferences(self) -> List[ghidra.trace.model.symbol.TraceReference]: ...

    @property
    def volatile(self) -> bool: ...