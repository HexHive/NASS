import ghidra.service.graph
import java.awt
import java.lang


class GraphDisplayOptionsBuilder(object):
    """
    Builder for building GraphDisplayOptions
    """





    def __init__(self, graphType: ghidra.service.graph.GraphType):
        """
        Create a new GraphDisplayOptionsBuilder
        @param graphType the {@link GraphType} of graphs that this instance configures.
        """
        ...



    def arrowLength(self, length: int) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the length of the arrows to display in the graph. The width will be sized proportionately.
        @param length the length the arrows to display in the graph
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def build(self) -> ghidra.service.graph.GraphDisplayOptions:
        """
        Returns a GraphTypeDisplayOptions as configured by this builder
        @return a GraphTypeDisplayOptions as configured by this builder
        """
        ...

    def defaultEdgeColor(self, c: java.awt.Color) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the default edge color for edges that don't have a registered edge type
        @param c the default edge color
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def defaultLayoutAlgorithm(self, string: unicode) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the name of the layout algorithm that will be used to initially layout the graph
        @param string the name of the layout algoritm to use to initially layout the graph
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def defaultVertexColor(self, c: java.awt.Color) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the default vertex color for vertexes that don't have a registered vertex type
        @param c the default vertex color
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def defaultVertexShape(self, vertexShape: ghidra.service.graph.VertexShape) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the default vertex shape for vertices that don't have a registered vertex type
        @param vertexShape the {@link VertexShape} to use as a default
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def edge(self, edgeType: unicode, color: java.awt.Color) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the color for edges of the given type
        @param edgeType the edge type to assign color
        @param color the color to use for the named edge type
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def edgeColorOverrideAttribute(self, colorAttributeKey: unicode) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the attribute used to override the color for a edge
        @param colorAttributeKey the attribute key to use for overriding an edge color
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def edgeSelectionColor(self, color: java.awt.Color) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the edge selection color
        @param color the edge selection color
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def labelPosition(self, labelPosition: ghidra.service.graph.GraphLabelPosition) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the vertex label position relative to vertex shape. This is only applicable if the
         {@link #useIcons(boolean)} is set to false.
        @param labelPosition the relative position to place the vertex label
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def maxNodeCount(self, maxNodeCount: int) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the maximum number of nodes a graph can have and still be displayed.
        @param maxNodeCount the maximum number of nodes
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def shapeOverrideAttribute(self, shapeAttributeKey: unicode) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the attribute used to override the shape for a vertex
        @param shapeAttributeKey the attribute key to use of shape override
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def toString(self) -> unicode: ...

    def useIcons(self, b: bool) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets drawing "mode" for the graph display. If true, vertices are drawn as scaled
         cached images with the label inside the shapes. If false, vertices are drawn as smaller
         shapes with labels drawn near the shapes.
        @param b true to use pre-rendered icon images
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def vertex(self, vertexType: unicode, vertexShape: ghidra.service.graph.VertexShape, color: java.awt.Color) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the shape and color for vertices of the given type
        @param vertexType the vertex type to assign shape and color
        @param vertexShape the shape to use for the named vertex type
        @param color the color to use for the named vertex type
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def vertexColorOverrideAttribute(self, colorAttributeKey: unicode) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the attribute used to override the color for a vertex
        @param colorAttributeKey the attribute key to use for overriding a vertex color
        @return this GraphDisplayOptionsBuilder
        """
        ...

    def vertexSelectionColor(self, color: java.awt.Color) -> ghidra.service.graph.GraphDisplayOptionsBuilder:
        """
        Sets the vertex selection color
        @param color the vertex selection color
        @return this GraphDisplayOptionsBuilder
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

