from typing import List
import java.lang


class GraphType(object):
    """
    Class that defines a new graph type. It defines the set of valid vertex and edge types
    """





    def __init__(self, __a0: unicode, __a1: unicode, __a2: List[object], __a3: List[object]): ...



    def containsEdgeType(self, edgeType: unicode) -> bool:
        """
        Test if the given string is a valid edge type
        @param edgeType the string to test for being a valid edge type
        @return true if the given string is a valid edge type
        """
        ...

    def containsVertexType(self, vertexType: unicode) -> bool:
        """
        Test if the given string is a valid vertex type
        @param vertexType the string to test for being a valid vertex type
        @return true if the given string is a valid vertex type
        """
        ...

    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDescription(self) -> unicode:
        """
        Returns a description for this type of graph
        @return a description for this type of graph
        """
        ...

    def getEdgeTypes(self) -> List[unicode]:
        """
        Returns a list of valid edge types for graphs of this type
        @return a list of valid edge types for graphs of this type
        """
        ...

    def getName(self) -> unicode:
        """
        Returns a name for this type of graph
        @return a name of this type of graph
        """
        ...

    def getOptionsName(self) -> unicode: ...

    def getVertexTypes(self) -> List[unicode]:
        """
        Returns a list of valid vertex types for graphs of this type
        @return a list of valid vertex types for graphs of this type
        """
        ...

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

    @property
    def description(self) -> unicode: ...

    @property
    def edgeTypes(self) -> List[object]: ...

    @property
    def name(self) -> unicode: ...

    @property
    def optionsName(self) -> unicode: ...

    @property
    def vertexTypes(self) -> List[object]: ...