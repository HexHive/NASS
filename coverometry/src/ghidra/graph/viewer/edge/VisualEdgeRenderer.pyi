import com.google.common.base
import edu.uci.ics.jung.algorithms.layout
import edu.uci.ics.jung.graph
import edu.uci.ics.jung.visualization
import edu.uci.ics.jung.visualization.renderers
import ghidra.graph.viewer
import java.awt
import java.lang


class VisualEdgeRenderer(edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer):
    """
    Edge render for the VisualGraph system
 
     Implementation Notes
 
     Jung Vertex/Edge Rendering
     Jung creates shapes for vertices (see VertexShapeFactory) that are centered.  They
     do this by getting the width/height of the shape and then creating an x/y value that is 
     half of the width and height, respectively.  This has the effect of the vertex appearing 
     centered over its connected edge.  We mimic that with our 
     VisualGraphVertexShapeTransformer so that our edge rendering code is similar to 
     Jung's.
     If we ever decide instead to not center our shapes, then this renderer would have to be
     updated to itself center the edge shape created herein, like this:
 
     Also, there are other spots in the system where we account for this center that would 
     have to be changed, such as the AbstractVisualGraphLayout, which needs the centering
     offsets to handle vertex clipping.

     When painting edges this renderer will paint colors based on the following states: default, 
     emphasized, hovered, focused and selected.   A focused edge is one that is part of the path 
     between focused vertices(such as when the vertex is hovered), whereas a selected edge is one 
     that has been selected by the user (see VisualEdge for details).   An edge is 
     'emphasized' when the user mouses over the edge (which is when the edge is hovered, not when the 
     vertex is hovered.  Each of these states may have a different color that can be changed by 
     calling the various setter methods on this renderer.  When painting, these colors are used along 
     with various different strokes to paint in an overlay fashion.
    """





    def __init__(self): ...



    @overload
    def drawSimpleEdge(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: ghidra.graph.viewer.VisualEdge) -> None: ...

    @overload
    def drawSimpleEdge(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: object) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDrawColor(self, __a0: edu.uci.ics.jung.graph.Graph, __a1: ghidra.graph.viewer.VisualEdge) -> java.awt.Color: ...

    def getEdgeArrowRenderingSupport(self) -> edu.uci.ics.jung.visualization.renderers.EdgeArrowRenderingSupport: ...

    def getEdgeShape(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.graph.Graph, __a2: ghidra.graph.viewer.VisualEdge, __a3: float, __a4: float, __a5: float, __a6: float, __a7: bool, __a8: java.awt.Shape) -> java.awt.Shape: ...

    def getFocusedColor(self, __a0: edu.uci.ics.jung.graph.Graph, __a1: ghidra.graph.viewer.VisualEdge) -> java.awt.Color: ...

    def getFullShape(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: ghidra.graph.viewer.VisualVertex) -> java.awt.Shape: ...

    def getHoveredColor(self, __a0: edu.uci.ics.jung.graph.Graph, __a1: ghidra.graph.viewer.VisualEdge) -> java.awt.Color: ...

    def getSelectedColor(self, __a0: edu.uci.ics.jung.graph.Graph, __a1: ghidra.graph.viewer.VisualEdge) -> java.awt.Color: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def paintEdge(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: object) -> None: ...

    def setDashingPatternOffset(self, dashingPatterOffset: float) -> None:
        """
        Sets the offset value for painting dashed lines.  This allows clients to animate the 
         lines being drawn for edges in the edge direction.
        @param dashingPatterOffset the offset value
        """
        ...

    def setDrawColorTransformer(self, transformer: com.google.common.base.Function) -> None:
        """
        Sets the color provider to use when drawing this edge.  This is also the color used to paint 
         an 'emphasized' edge.
        @param transformer the color provider
        """
        ...

    def setEdgeArrowRenderingSupport(self, __a0: edu.uci.ics.jung.visualization.renderers.EdgeArrowRenderingSupport) -> None: ...

    def setFocusedColorTransformer(self, transformer: com.google.common.base.Function) -> None:
        """
        Sets the color provider to use when drawing this edge when the edge is focused.
        @param transformer the color provider
        """
        ...

    def setHoveredColorTransformer(self, transformer: com.google.common.base.Function) -> None:
        """
        Sets the color provider to use when drawing this edge when the edge is in the hovered path.
        @param transformer the color provider
        """
        ...

    def setSelectedColorTransformer(self, transformer: com.google.common.base.Function) -> None:
        """
        Sets the color provider to use when drawing this edge when the edge is selected.
        @param transformer the color provider
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
    def dashingPatternOffset(self) -> None: ...  # No getter available.

    @dashingPatternOffset.setter
    def dashingPatternOffset(self, value: float) -> None: ...

    @property
    def drawColorTransformer(self) -> None: ...  # No getter available.

    @drawColorTransformer.setter
    def drawColorTransformer(self, value: com.google.common.base.Function) -> None: ...

    @property
    def focusedColorTransformer(self) -> None: ...  # No getter available.

    @focusedColorTransformer.setter
    def focusedColorTransformer(self, value: com.google.common.base.Function) -> None: ...

    @property
    def hoveredColorTransformer(self) -> None: ...  # No getter available.

    @hoveredColorTransformer.setter
    def hoveredColorTransformer(self, value: com.google.common.base.Function) -> None: ...

    @property
    def selectedColorTransformer(self) -> None: ...  # No getter available.

    @selectedColorTransformer.setter
    def selectedColorTransformer(self, value: com.google.common.base.Function) -> None: ...