import ghidra.program.model.address
import ghidra.trace.database.map
import ghidra.trace.model
import ghidra.trace.model.modules
import ghidra.util
import ghidra.util.database
import ghidra.util.database.spatial
import ghidra.util.database.spatial.rect
import java.lang


class DBTraceSection(ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData, ghidra.trace.model.modules.TraceSection):




    def __init__(self, __a0: ghidra.trace.database.module.DBTraceModuleSpace, __a1: ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree, __a2: ghidra.util.database.DBCachedObjectStore, __a3: db.DBRecord): ...



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

    def doHashCode(self) -> int: ...

    def enclosedBy(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> bool: ...

    @overload
    def encloses(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> bool: ...

    @overload
    def encloses(self, __a0: ghidra.util.database.spatial.BoundingShape) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getArea(self) -> float: ...

    def getBounds(self) -> ghidra.util.database.spatial.BoundingShape: ...

    def getCenter(self) -> ghidra.util.database.spatial.rect.Point2D: ...

    def getClass(self) -> java.lang.Class: ...

    def getEnd(self) -> ghidra.program.model.address.Address: ...

    def getKey(self) -> long: ...

    def getLifespan(self) -> ghidra.trace.model.Lifespan: ...

    def getMargin(self) -> float: ...

    def getModule(self) -> ghidra.trace.model.modules.TraceModule: ...

    def getName(self) -> unicode: ...

    def getObjectKey(self) -> ghidra.util.database.ObjectKey: ...

    def getParentKey(self) -> long: ...

    def getPath(self) -> unicode: ...

    def getRange(self) -> ghidra.program.model.address.AddressRange: ...

    def getShape(self) -> ghidra.util.database.spatial.BoundedShape: ...

    def getSpace(self) -> ghidra.util.database.spatial.rect.EuclideanSpace2D: ...

    def getStart(self) -> ghidra.program.model.address.Address: ...

    def getTableName(self) -> unicode: ...

    def getTrace(self) -> ghidra.trace.model.Trace: ...

    def getX1(self) -> object: ...

    def getX2(self) -> object: ...

    def getY1(self) -> object: ...

    def getY2(self) -> object: ...

    def hashCode(self) -> int: ...

    @overload
    def immutable(self, __a0: ghidra.program.model.address.Address, __a1: ghidra.program.model.address.Address, __a2: long, __a3: long) -> ghidra.trace.model.TraceAddressSnapRange: ...

    @overload
    def immutable(self, __a0: object, __a1: object, __a2: object, __a3: object) -> ghidra.util.database.spatial.rect.Rectangle2D: ...

    def intersection(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> ghidra.util.database.spatial.rect.Rectangle2D: ...

    def intersects(self, __a0: ghidra.util.database.spatial.rect.Rectangle2D) -> bool: ...

    @overload
    def isDeleted(self) -> bool: ...

    @overload
    def isDeleted(self, __a0: ghidra.util.Lock) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setInvalid(self) -> None: ...

    def setName(self, __a0: unicode) -> None: ...

    def setParentKey(self, __a0: long) -> None: ...

    @overload
    def setShape(self, __a0: ghidra.trace.model.TraceAddressSnapRange) -> None: ...

    @overload
    def setShape(self, __a0: ghidra.util.database.spatial.BoundedShape) -> None: ...

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
    def module(self) -> ghidra.trace.database.module.DBTraceModule: ...

    @property
    def name(self) -> unicode: ...

    @name.setter
    def name(self, value: unicode) -> None: ...

    @property
    def path(self) -> unicode: ...

    @property
    def trace(self) -> ghidra.trace.model.Trace: ...