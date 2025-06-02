import ghidra.service.graph
import java.lang


class GraphTypeBuilder(object):
    """
    Builder class for building new GraphTypes
    """





    def __init__(self, name: unicode):
        """
        Create a new builder
        @param name the name of the new {@link GraphType}
        """
        ...



    def build(self) -> ghidra.service.graph.GraphType:
        """
        Builds a new GraphType
        @return a new GraphType
        """
        ...

    def description(self, text: unicode) -> ghidra.service.graph.GraphTypeBuilder:
        """
        Sets the description for the {@link GraphType}
        @param text the description
        @return this GraphTypeBuilder
        """
        ...

    def edgeType(self, type: unicode) -> ghidra.service.graph.GraphTypeBuilder:
        """
        Defines a new edge type
        @param type a string that names a new edge type
        @return this GraphTypeBuilder
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def vertexType(self, type: unicode) -> ghidra.service.graph.GraphTypeBuilder:
        """
        Defines a new vertex type
        @param type a string that names a new vertex type
        @return this GraphTypeBuilder
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

