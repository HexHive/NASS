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
import ghidra.util.database
import ghidra.util.database.spatial
import ghidra.util.database.spatial.rect
import java.io
import java.lang
import java.nio
import java.util


class DBTraceData(ghidra.trace.database.listing.AbstractDBTraceCodeUnit, ghidra.trace.database.listing.DBTraceDefinedDataAdapter):




    def __init__(self, __a0: ghidra.trace.database.listing.DBTraceCodeSpace, __a1: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree, __a2: ghidra.util.database.DBCachedObjectStore, __a3: db.DBRecord): ...



    def addMnemonicReference(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.symbol.RefType, __a2: ghidra.program.model.symbol.SourceType) -> None: ...

    def addOperandReference(self, __a0: int, __a1: ghidra.program.model.address.Address, __a2: ghidra.program.model.symbol.RefType, __a3: ghidra.program.model.symbol.SourceType) -> None: ...

    def addValueReference(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.symbol.RefType) -> None: ...

    def clearAllSettings(self) -> None: ...

    def clearSetting(self, __a0: unicode) -> None: ...

    def compareTo(self, __a0: ghidra.program.model.address.Address) -> int: ...

    @overload
    def computeAreaIntersection(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> float: ...

    @overload
    def computeAreaIntersection(self, __a0: ghidra.util.database.spatial.BoundingShape) -> float: ...

    @overload
    def computeAreaUnionBounds(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> float: ...

    @overload
    def computeAreaUnionBounds(self, __a0: ghidra.util.database.spatial.BoundingShape) -> float: ...

    @overload
    def computeCentroidDistance(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> float: ...

    @overload
    def computeCentroidDistance(self, __a0: ghidra.util.database.spatial.BoundingShape) -> float: ...

    @overload
    def contains(self, __a0: ghidra.util.database.spatial.rect.Point2D) -> bool: ...

    @overload
    def contains(self, __a0: object, __a1: object) -> bool: ...

    def delete(self) -> None: ...

    def description(self) -> unicode: ...

    def doEquals(self, __a0: object) -> bool: ...

    def doGetComponent(self, __a0: List[int], __a1: int) -> ghidra.trace.database.listing.DBTraceDefinedDataAdapter: ...

    def doGetComponentCache(self) -> List[ghidra.trace.database.listing.AbstractDBTraceDataComponent]: ...

    def doHashCode(self) -> int: ...

    def doToString(self) -> unicode: ...

    def enclosedBy(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> bool: ...

    @overload
    def encloses(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> bool: ...

    @overload
    def encloses(self, __a0: ghidra.util.database.spatial.BoundingShape) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    @overload
    def getAddress(self) -> ghidra.program.model.address.Address: ...

    @overload
    def getAddress(self, __a0: int) -> ghidra.program.model.address.Address: ...

    def getAddressString(self, __a0: bool, __a1: bool) -> unicode: ...

    def getArea(self) -> float: ...

    @overload
    def getBaseDataType(self) -> ghidra.program.model.data.DataType: ...

    @overload
    @staticmethod
    def getBaseDataType(__a0: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType: ...

    def getBigInteger(self, __a0: int, __a1: int, __a2: bool) -> long: ...

    def getBounds(self) -> ghidra.util.database.spatial.BoundingShape: ...

    def getByte(self, __a0: int) -> int: ...

    @overload
    def getBytes(self) -> List[int]: ...

    @overload
    def getBytes(self, __a0: List[int], __a1: int) -> int: ...

    @overload
    def getBytes(self, __a0: java.nio.ByteBuffer, __a1: int) -> int: ...

    def getBytesInCodeUnit(self, __a0: List[int], __a1: int) -> None: ...

    def getBytesInFull(self, __a0: int, __a1: int) -> java.nio.ByteBuffer: ...

    def getCenter(self) -> ghidra.util.database.spatial.rect.Point2D: ...

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

    def getKey(self) -> long: ...

    def getLabel(self) -> unicode: ...

    def getLanguage(self) -> ghidra.program.model.lang.Language: ...

    def getLength(self) -> int: ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan: ...

    @overload
    def getLong(self, __a0: int) -> long: ...

    @overload
    def getLong(self, __a0: unicode) -> long: ...

    def getMargin(self) -> float: ...

    def getMaxAddress(self) -> ghidra.program.model.address.Address: ...

    def getMemory(self) -> ghidra.program.model.mem.Memory: ...

    def getMinAddress(self) -> ghidra.program.model.address.Address: ...

    def getMnemonicReferences(self) -> List[ghidra.program.model.symbol.Reference]: ...

    def getMnemonicString(self) -> unicode: ...

    def getNames(self) -> List[unicode]: ...

    def getNumComponents(self) -> int: ...

    def getNumOperands(self) -> int: ...

    def getObjectKey(self) -> ghidra.util.database.ObjectKey: ...

    def getObjectProperty(self, __a0: unicode) -> ghidra.util.Saveable: ...

    def getOperandReferences(self, __a0: int) -> List[ghidra.trace.database.symbol.DBTraceReference]: ...

    def getParent(self) -> ghidra.program.model.listing.Data: ...

    def getParentKey(self) -> long: ...

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

    def getShape(self) -> ghidra.util.database.spatial.BoundedShape: ...

    def getShort(self, __a0: int) -> int: ...

    def getSpace(self) -> ghidra.util.database.spatial.rect.EuclideanSpace2D: ...

    def getStartSnap(self) -> long: ...

    def getString(self, __a0: unicode) -> unicode: ...

    def getStringProperty(self, __a0: unicode) -> unicode: ...

    def getSuggestedValues(self, __a0: ghidra.docking.settings.StringSettingsDefinition) -> List[unicode]: ...

    def getSymbols(self) -> List[ghidra.program.model.symbol.Symbol]: ...

    def getTableName(self) -> unicode: ...

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

    def getX1(self) -> object: ...

    def getX2(self) -> object: ...

    def getY1(self) -> object: ...

    def getY2(self) -> object: ...

    def hasMutability(self, __a0: int) -> bool: ...

    def hasProperty(self, __a0: unicode) -> bool: ...

    def hasStringValue(self) -> bool: ...

    def hashCode(self) -> int: ...

    @overload
    def immutable(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address, __a2: long, __a3: long) -> ghidra.trace.model.TraceAddressSnapRange: ...

    @overload
    def immutable(self, __a0: object, __a1: object, __a2: object, __a3: object) -> ghidra.util.database.spatial.rect.Rectangle2D: ...

    def intersection(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> ghidra.util.database.spatial.rect.Rectangle2D: ...

    def intersects(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> bool: ...

    def isArray(self) -> bool: ...

    def isBigEndian(self) -> bool: ...

    def isChangeAllowed(self, __a0: ghidra.docking.settings.SettingsDefinition) -> bool: ...

    def isConstant(self) -> bool: ...

    def isDefined(self) -> bool: ...

    @overload
    def isDeleted(self) -> bool: ...

    @overload
    def isDeleted(self, __a0: ghidra.util.Lock) -> bool: ...

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

    def setInvalid(self) -> None: ...

    def setLong(self, __a0: unicode, __a1: long) -> None: ...

    def setParentKey(self, __a0: long) -> None: ...

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

    @overload
    def setShape(self, __a0: ghidra.trace.model.TraceAddressSnapRange) -> None: ...

    @overload
    def setShape(self, __a0: ghidra.util.database.spatial.BoundedShape) -> None: ...

    def setStackReference(self, __a0: int, __a1: int, __a2: ghidra.program.model.symbol.SourceType, __a3: ghidra.program.model.symbol.RefType) -> None: ...

    def setString(self, __a0: unicode, __a1: unicode) -> None: ...

    def setTypedProperty(self, __a0: unicode, __a1: object) -> None: ...

    def setValue(self, __a0: unicode, __a1: object) -> None: ...

    @overload
    def shapeEquals(self, __a0: ghidra.trace.model.TraceAddressSnapRange) -> bool: ...

    @overload
    def shapeEquals(self, __a0: ghidra.util.database.spatial.BoundedShape) -> bool: ...

    def toString(self) -> unicode: ...

    @overload
    def unionBounds(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> ghidra.util.database.spatial.rect.Rectangle2D: ...

    @overload
    def unionBounds(self, __a0: ghidra.util.database.spatial.BoundingShape) -> ghidra.util.database.spatial.BoundingShape: ...

    @staticmethod
    def unionIterable(__a0: java.lang.Iterable) -> ghidra.util.database.spatial.BoundingShape: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def baseDataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def componentIndex(self) -> int: ...

    @property
    def componentLevel(self) -> int: ...

    @property
    def componentPath(self) -> List[int]: ...

    @property
    def componentPathName(self) -> unicode: ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType: ...

    @property
    def defaultSettings(self) -> ghidra.docking.settings.Settings: ...

    @property
    def endSnap(self) -> long: ...

    @endSnap.setter
    def endSnap(self, value: long) -> None: ...

    @property
    def fieldName(self) -> unicode: ...

    @property
    def language(self) -> ghidra.program.model.lang.Language: ...

    @property
    def parent(self) -> ghidra.trace.database.listing.DBTraceDefinedDataAdapter: ...

    @property
    def parentOffset(self) -> int: ...

    @property
    def pathName(self) -> unicode: ...

    @property
    def platform(self) -> ghidra.trace.model.guest.TracePlatform: ...

    @property
    def root(self) -> ghidra.trace.database.listing.DBTraceData: ...

    @property
    def rootOffset(self) -> int: ...