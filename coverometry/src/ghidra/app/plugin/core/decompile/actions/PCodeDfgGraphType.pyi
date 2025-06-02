from typing import List
import ghidra.service.graph
import java.lang


class PCodeDfgGraphType(ghidra.service.graph.GraphType):
    ADDRESS_TIED: unicode = u'Address Tied'
    BETWEEN_BLOCKS: unicode = u'Between Blocks'
    CONSTANT: unicode = u'Constant'
    DEFAULT_EDGE: unicode = u'Default'
    DEFAULT_VERTEX: unicode = u'Default'
    OP: unicode = u'Op'
    PERSISTENT: unicode = u'Persistent'
    REGISTER: unicode = u'Register'
    UNIQUE: unicode = u'Unique'
    WITHIN_BLOCK: unicode = u'Within Block'



    def __init__(self): ...



    def containsEdgeType(self, __a0: unicode) -> bool: ...

    def containsVertexType(self, __a0: unicode) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode: ...

    def getEdgeTypes(self) -> List[object]: ...

    def getName(self) -> unicode: ...

    def getOptionsName(self) -> unicode: ...

    def getVertexTypes(self) -> List[object]: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

