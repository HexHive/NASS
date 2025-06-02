import docking
import ghidra.framework.options
import ghidra.service.graph
import ghidra.util
import java.awt
import java.lang
import javax.swing.event


class GraphDisplayOptions(object, ghidra.framework.options.OptionsChangeListener):
    """
    Class for managing graph display options. This includes color options for each vertex
     and edge type and shapes for vertex types.
    """





    def __init__(self, graphType: ghidra.service.graph.GraphType):
        """
        Constructs a new GraphTypeDisplayOptions for the given {@link GraphType}
        @param graphType The {@link GraphType} for which to define display options
        """
        ...



    def addChangeListener(self, listener: javax.swing.event.ChangeListener) -> None:
        """
        Adds a ChangeListener to be notified when display options change
        @param listener the listener to be notified.
        """
        ...

    def displayEditor(self, tool: docking.Tool, help: ghidra.util.HelpLocation) -> None:
        """
        Pop up a dialog for editing these graph display options. If the options
         are registered with tool options, show the tool options with the appropriate
         graph options selected. Otherwise, show an editor for locally editing these
         options.
        @param tool the tool
        @param help the help location to use if the options are edited locally
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getArrowLength(self) -> int:
        """
        Returns the length of the arrow. The width will be proportional to the length.
         Note: this option is not exposed in the Options because it is too specific to a graph
         instance and wouldn't be appropriate to apply to shared options.
        @return the size if the arrow
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultEdgeColor(self) -> java.awt.Color:
        """
        Returns the default color for edges that don't have an edge type set
        @return the default color for edges that don't have an edge type set
        """
        ...

    def getDefaultLayoutAlgorithmNameLayout(self) -> unicode:
        """
        Returns the name of the default graph layout algorithm
        @return the name of the default graph layout algorithms
        """
        ...

    def getDefaultVertexColor(self) -> java.awt.Color:
        """
        Returns the default color for vertices that don't have an vertex type set
        @return the default color for vertices that don't have an vertex type set
        """
        ...

    def getDefaultVertexShape(self) -> ghidra.service.graph.VertexShape:
        """
        returns the {@link VertexShape} for any vertex that has not vertex type defined
        @return the {@link VertexShape} for any vertex that has not vertex type defined
        """
        ...

    @overload
    def getEdgeColor(self, edgeType: unicode) -> java.awt.Color:
        """
        Returns the color for the given edge type
        @param edgeType the edge type whose color is to be determined.
        @return the color for the given edge type.
        """
        ...

    @overload
    def getEdgeColor(self, edge: ghidra.service.graph.AttributedEdge) -> java.awt.Color:
        """
        Returns the color that will be used to draw the edge
        @param edge the edge for which to get the color
        @return the color that will be used to draw the edge
        """
        ...

    def getEdgeColorOverrideAttributeKey(self) -> unicode:
        """
        Returns the attribute key that can be used to override the color of an edge
        @return the attribute key that can be used to override the color of an edge
        """
        ...

    def getEdgePriority(self, edgeType: unicode) -> int:
        """
        Returns the priority for the given edge type. This is used by layout algorithms to
         determine which edges should have more influence on the layout.
        @param edgeType the edge type for which to get it's priority
        @return the priority for the given edge type
        """
        ...

    def getEdgeSelectionColor(self) -> java.awt.Color:
        """
        Returns the color for edge selections
        @return the color fore edge selections
        """
        ...

    def getFavoredEdgeType(self) -> unicode:
        """
        Returns the edge type that is the preferred edge for layout purposes
        @return the edge type that is the preferred edge for layout purposes
        """
        ...

    def getFont(self) -> java.awt.Font:
        """
        Returns the font being used to render vertex labels
        @return the font being used to render vertex labels
        """
        ...

    def getGraphType(self) -> ghidra.service.graph.GraphType:
        """
        Returns the {@link GraphType} that this object provides display options for
        @return the {@link GraphType} that this object provides display options for
        """
        ...

    def getLabelPosition(self) -> ghidra.service.graph.GraphLabelPosition:
        """
        Returns the label position relative to the vertex. Note this is only relevant 
         if {@link #usesIcons()} is false
        @return the label position relative to the vertex
        """
        ...

    def getMaxNodeCount(self) -> int:
        """
        Returns the maximum number of nodes that can be in a displayed graph
        @return the maximum number of nodes that can be in a displayed graph
        """
        ...

    def getRootOptionsName(self) -> unicode:
        """
        Returns the name for the root Options name for this {@link GraphDisplayOptions}
        @return the name for the root Options name for this {@link GraphDisplayOptions}
        """
        ...

    @overload
    def getVertexColor(self, vertexType: unicode) -> java.awt.Color:
        """
        Returns the color for the given vertex type
        @param vertexType the vertex type to get the color for
        @return the color for the given vertex type
        """
        ...

    @overload
    def getVertexColor(self, vertex: ghidra.service.graph.AttributedVertex) -> java.awt.Color:
        """
        Returns the color that will be used to draw the vertex
        @param vertex the vertex for which to get the color
        @return the color that will be used to draw the vertex
        """
        ...

    def getVertexColorOverrideAttributeKey(self) -> unicode:
        """
        Returns the attribute key that can be used to override the color of a vertex. Normally,
         a vertex is colored based on its vertex type. However, if this value is non-null, a vertex
         can override its color by setting an attribute using this key name.
        @return the attribute key that can be used to override the color of a vertex
        """
        ...

    def getVertexLabel(self, vertex: ghidra.service.graph.AttributedVertex) -> unicode:
        """
        Returns the text that will be displayed as the label for the given vertex
        @param vertex the vertex for which to get label text
        @return the text that will be displayed as the label for the given vertex
        """
        ...

    def getVertexLabelOverride(self) -> unicode:
        """
        Returns the attribute key that can override the vertices label text
        @return the attribute key that can override the vertices label text
        """
        ...

    def getVertexSelectionColor(self) -> java.awt.Color:
        """
        Returns the vertex selection color
        @return the vertex selection color
        """
        ...

    @overload
    def getVertexShape(self, vertexType: unicode) -> ghidra.service.graph.VertexShape:
        """
        Returns the {@link VertexShape} for vertices that have the given vertex type
        @param vertexType the vertex type for which to get its asigned shape
        @return the {@link VertexShape} for vertices that have the given vertex type
        """
        ...

    @overload
    def getVertexShape(self, vertex: ghidra.service.graph.AttributedVertex) -> ghidra.service.graph.VertexShape:
        """
        Returns the {@link VertexShape} that will be used to draw the vertex's shape
        @param vertex the vertex for which to get the shape
        @return the {@link VertexShape} that will be used to draw the vertex's shape
        """
        ...

    def getVertexShapeOverrideAttributeKey(self) -> unicode:
        """
        Returns the attribute key that can be used to override the shape of a vertex. Normally,
         a vertex has a shape based on its vertex type. However, if this value is non-null, a vertex
         can override its shape by setting an attribute using this key name.
        @return the attribute key that can be used to override the shape of a vertex
        """
        ...

    def hashCode(self) -> int: ...

    def initializeFromOptions(self, tool: docking.Tool) -> None:
        """
        Loads values from tool options
        @param tool the tool from which to update values.
        """
        ...

    def isRegisteredWithTool(self) -> bool:
        """
        Returns true if this {@link GraphDisplayOptions} instance has been constructed with
         a tool for getting/saving option values in the tool options
        @return true if this {@link GraphDisplayOptions} instance is connected to tool options
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def optionsChanged(self, options: ghidra.framework.options.ToolOptions, optionName: unicode, oldValue: object, newValue: object) -> None: ...

    def removeChangeListener(self, listener: javax.swing.event.ChangeListener) -> None:
        """
        Removes the listener so that it won't be notified of changes any longer
        @param listener the listener to be removed
        """
        ...

    def setArrowLength(self, length: int) -> None:
        """
        Sets the length of the arrow. The width will be proportional to the length.
         Note: this option is not exposed in the Options because it is too specific to a graph
         instance and wouldn't be appropriate to apply to shared options.
        @param length the size of the arrow
        """
        ...

    @overload
    def setDefaultEdgeColor(self, themeColorId: unicode) -> None:
        """
        Sets the default color to be used by vertices that don't have a vertex type set. The
         color is set via a themeColorId, which means the client defined a theme color for this.
        @param themeColorId the theme color id to use for the default vertex color
        """
        ...

    @overload
    def setDefaultEdgeColor(self, color: java.awt.Color) -> None:
        """
        Sets the default color to be used by edges that don't have a edge type set
        @param color the default edge shape
        """
        ...

    def setDefaultLayoutAlgorithmName(self, defaultLayout: unicode) -> None:
        """
        Sets the name of the default layout algorithm
        @param defaultLayout the name of the layout algorithm to use by default
        """
        ...

    @overload
    def setDefaultVertexColor(self, themeColorId: unicode) -> None:
        """
        Sets the default color to be used by vertices that don't have a vertex type set. The
         color is set via a themeColorId, which means the client defined a theme color for this.
        @param themeColorId the theme color id to use for the default vertex color
        """
        ...

    @overload
    def setDefaultVertexColor(self, color: java.awt.Color) -> None:
        """
        Sets the default color to be used by vertices that don't have a vertex type set
        @param color the default vertex shape
        """
        ...

    def setDefaultVertexShape(self, shape: ghidra.service.graph.VertexShape) -> None:
        """
        Sets the default shape to be used by vertices that don't have a vertex type set
        @param shape the default vertex shape
        """
        ...

    @overload
    def setEdgeColor(self, edgeType: unicode, themeColorId: unicode) -> None:
        """
        Sets the edge color using a theme color id. By using a theme color id, this property
         is eligible to be registered as a tool option.
        @param edgeType the edge type for which to set its color
        @param themeColorId the theme color id of the color for this edge type
        """
        ...

    @overload
    def setEdgeColor(self, edgeType: unicode, color: java.awt.Color) -> None:
        """
        Sets the color for edges with the given edge type
        @param edgeType the edge type for which to set its color
        @param color the new color for edges with the given edge type
        """
        ...

    def setEdgeColorOverrideAttributeKey(self, attributeKey: unicode) -> None:
        """
        Sets the attribute key that can be used to override the color for an edge. Normally, the
         color is determined by the edge type, which will be mapped to a color
        @param attributeKey the attribute key that, if set, will be used to define the edge's color
        """
        ...

    @overload
    def setEdgeSelectionColor(self, themeColorId: unicode) -> None:
        """
        Sets the edge selection color using the theme color defined by the given color id. This
         method will allow the property to be registered to the tool options.
        @param themeColorId the color id to use for highlighting edges.
        """
        ...

    @overload
    def setEdgeSelectionColor(self, edgeSelectionColor: java.awt.Color) -> None:
        """
        Sets the edge selection color. Using the method means the color will not appear in the
         tool options.
        @param edgeSelectionColor color to use for highlighting selected edges
        """
        ...

    def setFavoredEdgeType(self, favoredEdgeType: unicode) -> None:
        """
        Sets the favored edge type. The favored edge type is used to influence layout algorithms
        @param favoredEdgeType the edge type that is to be favored by layout algorithms
        """
        ...

    @overload
    def setFont(self, themeFontId: unicode) -> None: ...

    @overload
    def setFont(self, font: java.awt.Font) -> None:
        """
        Sets the font to use for drawing vertex labels
        @param font the font to use for drawing vertex labels
        """
        ...

    def setLabelPosition(self, labelPosition: ghidra.service.graph.GraphLabelPosition) -> None:
        """
        Sets the label position relative to the vertex. Note this is only relevant
         if {@link #usesIcons()} is false.
        @param labelPosition the {@link GraphLabelPosition} to use for rendering vertex labels
        """
        ...

    def setMaxNodeCount(self, maxNodeCount: int) -> None:
        """
        Sets the maximum number of nodes a graph can have and still be displayed. Be careful, 
         setting this value too high can result in Ghidra running out of memory and/or 
         making the system very sluggish.
        @param maxNodeCount the maximum number of nodes a graph can have and still be displayed.
        """
        ...

    def setUsesIcons(self, b: bool) -> None:
        """
        Sets whether the graph rendering mode is to use icons or not. If using icons, the label and
         shape are drawn together into a cached icon. Otherwise, the shapes are drawn on the fly and
         labeled separately.
        @param b true to render in icon mode.
        """
        ...

    @overload
    def setVertexColor(self, vertexType: unicode, themeColorId: unicode) -> None:
        """
        Sets the vertex color using a theme color id. By using a theme color id, this property
         is eligible to be registered as a tool option.
        @param vertexType the vertex type for which to set its color
        @param themeColorId the theme color id of the color for this vertex type
        """
        ...

    @overload
    def setVertexColor(self, vertexType: unicode, color: java.awt.Color) -> None:
        """
        Sets the color for vertices with the given vertex type. Note that this method does not
         allow the vertex color to be registered in tool options. 
         See {@link #setVertexColor(String, String)}.
        @param vertexType the vertex type for which to set its color
        @param color the color to use for vertices with the given vertex type
        """
        ...

    def setVertexColorOverrideAttributeKey(self, attributeKey: unicode) -> None:
        """
        Sets the attribute key that can be used to override the color for a vertex. Normally, the
         color is determined by the vertex type, which will be mapped to a color
        @param attributeKey the attribute key that, if set, will be used to define the vertice's color
        """
        ...

    def setVertexLabelOverrideAttributeKey(self, attributeKey: unicode) -> None:
        """
        Sets the attribute key that can be used to override the label text shown for the vertex.
         Normally, the vertex's name is shown as the label.
        @param attributeKey the attribute key that, if set, will be used to define the vertice's label
        """
        ...

    @overload
    def setVertexSelectionColor(self, themeColorId: unicode) -> None:
        """
        Sets the vertex selection color using the theme color defined by the given color id. This
         method will allow the property to be registered to the tool options.
        @param themeColorId the color id to use for highlighting vertices.
        """
        ...

    @overload
    def setVertexSelectionColor(self, vertexSelectionColor: java.awt.Color) -> None:
        """
        Sets the vertex selection color. Use this method only if this color does not appear in
         the tool options.
        @param vertexSelectionColor the color to use for highlighting selected vertices
        """
        ...

    def setVertexShape(self, vertexType: unicode, vertexShape: ghidra.service.graph.VertexShape) -> None:
        """
        Sets the {@link VertexShape} to use for vertices with the given vertex type
        @param vertexType the vertex type for which to set its shape
        @param vertexShape the {@link VertexShape} to use for vertices with the given vertex type
        """
        ...

    def setVertexShapeOverrideAttributeKey(self, attributeKey: unicode) -> None:
        """
        Sets the attribute key that can be used to override the shape for a vertex. Normally, the
         shape is determined by the vertex type, which will be mapped to a shape
        @param attributeKey the attribute key that, if set, will be used to define the vertice's shape
        """
        ...

    def toString(self) -> unicode: ...

    def usesIcons(self) -> bool:
        """
        Returns true if the rendering mode is to use icons for the vertices. If using
         icons, the label is drawn inside the shape.
        @return true if the rendering mode is to use icons.
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def arrowLength(self) -> int: ...

    @arrowLength.setter
    def arrowLength(self, value: int) -> None: ...

    @property
    def defaultEdgeColor(self) -> java.awt.Color: ...

    @property
    def defaultLayoutAlgorithmName(self) -> None: ...  # No getter available.

    @defaultLayoutAlgorithmName.setter
    def defaultLayoutAlgorithmName(self, value: unicode) -> None: ...

    @property
    def defaultLayoutAlgorithmNameLayout(self) -> unicode: ...

    @property
    def defaultVertexColor(self) -> java.awt.Color: ...

    @property
    def defaultVertexShape(self) -> ghidra.service.graph.VertexShape: ...

    @defaultVertexShape.setter
    def defaultVertexShape(self, value: ghidra.service.graph.VertexShape) -> None: ...

    @property
    def edgeColorOverrideAttributeKey(self) -> unicode: ...

    @edgeColorOverrideAttributeKey.setter
    def edgeColorOverrideAttributeKey(self, value: unicode) -> None: ...

    @property
    def edgeSelectionColor(self) -> java.awt.Color: ...

    @property
    def favoredEdgeType(self) -> unicode: ...

    @favoredEdgeType.setter
    def favoredEdgeType(self, value: unicode) -> None: ...

    @property
    def font(self) -> java.awt.Font: ...

    @property
    def graphType(self) -> ghidra.service.graph.GraphType: ...

    @property
    def labelPosition(self) -> ghidra.service.graph.GraphLabelPosition: ...

    @labelPosition.setter
    def labelPosition(self, value: ghidra.service.graph.GraphLabelPosition) -> None: ...

    @property
    def maxNodeCount(self) -> int: ...

    @maxNodeCount.setter
    def maxNodeCount(self, value: int) -> None: ...

    @property
    def registeredWithTool(self) -> bool: ...

    @property
    def rootOptionsName(self) -> unicode: ...

    @property
    def vertexColorOverrideAttributeKey(self) -> unicode: ...

    @vertexColorOverrideAttributeKey.setter
    def vertexColorOverrideAttributeKey(self, value: unicode) -> None: ...

    @property
    def vertexLabelOverride(self) -> unicode: ...

    @property
    def vertexLabelOverrideAttributeKey(self) -> None: ...  # No getter available.

    @vertexLabelOverrideAttributeKey.setter
    def vertexLabelOverrideAttributeKey(self, value: unicode) -> None: ...

    @property
    def vertexSelectionColor(self) -> java.awt.Color: ...

    @property
    def vertexShapeOverrideAttributeKey(self) -> unicode: ...

    @vertexShapeOverrideAttributeKey.setter
    def vertexShapeOverrideAttributeKey(self, value: unicode) -> None: ...