import ghidra.graph
import java.lang
import java.util


class GraphPath(object):
    """
    Class for storing paths with fast "contains" method.

     Note: a path can only contain a vertex once.
    """





    @overload
    def __init__(self):
        """
        Default constructor.
        """
        ...

    @overload
    def __init__(self, __a0: object): ...



    def add(self, __a0: object) -> None: ...

    def contains(self, __a0: object) -> bool: ...

    def copy(self) -> ghidra.graph.GraphPath:
        """
        Creates a new GraphPath object by performing a shallow copy on another GraphPath object.
        @return the new shallow copy of the original GraphPath object
        """
        ...

    def depth(self, __a0: object) -> int: ...

    def equals(self, __a0: object) -> bool: ...

    def get(self, depth: int) -> V:
        """
        Get vertex that is specified by the parameter.
        @param depth of the vertex to retrieve
        @return the vertex
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCommonStartPath(self, other: ghidra.graph.GraphPath) -> ghidra.graph.GraphPath:
        """
        Return all vertices that two GraphPaths have in common. For example if you have
         a-b-c-d-e-f and a-b-c-d-k-l-z, the common start path will be a-b-c-d. If there is no common
         start path, an empty GraphPath object is returned.
        @param other the other GraphPath to get the common start path of
        @return a new GraphPath object containing the common start path vertices
        """
        ...

    def getLast(self) -> V:
        """
        Get last vertex of GraphPath.
        @return last vertex of GraphPath
        """
        ...

    def getPredecessors(self, __a0: object) -> java.util.Set: ...

    def getSuccessors(self, __a0: object) -> java.util.Set: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeLast(self) -> V:
        """
        Remove the last vertex of the GraphPath.
        @return the removed vertex
        """
        ...

    def size(self) -> int:
        """
        Return the size of the GraphPath.
        @return size of the GraphPath
        """
        ...

    def startsWith(self, otherPath: ghidra.graph.GraphPath) -> bool:
        """
        Check if a GraphPath starts with another GraphPath.
        @param otherPath the other GraphPath we are checking
        @return true if the current GraphPath starts with otherPath, false otherwise
        """
        ...

    def subPath(self, start: int, end: int) -> ghidra.graph.GraphPath:
        """
        Get a part of the whole GraphPath, similar to substring with strings.
        @param start the start of the sub-path of the GraphPath
        @param end the end of the sub-path of the GraphPath
        @return a new GraphPath which is a sub-path of the original GraphPath from start to end
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
    def last(self) -> object: ...