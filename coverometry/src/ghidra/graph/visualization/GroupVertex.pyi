import ghidra.graph.visualization
import ghidra.service.graph
import java.lang
import java.util


class GroupVertex(ghidra.service.graph.AttributedVertex):








    def clear(self) -> None: ...

    def entrySet(self) -> java.util.Set: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def flatten(__a0: java.util.Collection) -> java.util.Set: ...

    def getAttribute(self, __a0: unicode) -> unicode: ...

    def getAttributes(self) -> java.util.Map: ...

    def getClass(self) -> java.lang.Class: ...

    def getContainedVertices(self) -> java.util.Set: ...

    def getDescription(self) -> unicode: ...

    def getFirst(self) -> ghidra.service.graph.AttributedVertex: ...

    def getId(self) -> unicode: ...

    def getName(self) -> unicode: ...

    def getVertexType(self) -> unicode: ...

    @staticmethod
    def groupVertices(__a0: java.util.Collection) -> ghidra.graph.visualization.GroupVertex: ...

    def hasAttribute(self, __a0: unicode) -> bool: ...

    def hashCode(self) -> int: ...

    def isEmpty(self) -> bool: ...

    def keys(self) -> java.util.Set: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def putAttributes(self, __a0: java.util.Map) -> None: ...

    def removeAttribute(self, __a0: unicode) -> unicode: ...

    def setAttribute(self, __a0: unicode, __a1: unicode) -> unicode: ...

    def setDescription(self, __a0: unicode) -> unicode: ...

    def setName(self, __a0: unicode) -> None: ...

    def setVertexType(self, __a0: unicode) -> None: ...

    def size(self) -> int: ...

    def toString(self) -> unicode: ...

    def values(self) -> java.util.Collection: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def containedVertices(self) -> java.util.Set: ...

    @property
    def first(self) -> ghidra.service.graph.AttributedVertex: ...