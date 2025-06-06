import edu.uci.ics.jung.algorithms.layout
import edu.uci.ics.jung.visualization
import edu.uci.ics.jung.visualization.renderers
import ghidra.graph.viewer
import java.lang


class VisualGraphRenderer(edu.uci.ics.jung.visualization.renderers.BasicRenderer):
    """
    This was created to add the ability to paint selected vertices above other vertices.  We need
     this since the Jung Graph has no notion of Z-order and thus does not let us specify that any
     particular vertex should be above another one.
    """

    DEBUG_ROW_COL_MAP: java.util.Map



    def __init__(self, edgeLabelRenderer: edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getEdgeLabelRenderer(self) -> edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel: ...

    def getEdgeRenderer(self) -> edu.uci.ics.jung.visualization.renderers.Renderer.Edge: ...

    def getVertexLabelRenderer(self) -> edu.uci.ics.jung.visualization.renderers.Renderer.VertexLabel: ...

    def getVertexRenderer(self) -> edu.uci.ics.jung.visualization.renderers.Renderer.Vertex: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def render(self, renderContext: edu.uci.ics.jung.visualization.RenderContext, layout: edu.uci.ics.jung.algorithms.layout.Layout) -> None: ...

    def renderEdge(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: object) -> None: ...

    @overload
    def renderEdgeLabel(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: ghidra.graph.viewer.VisualEdge) -> None: ...

    @overload
    def renderEdgeLabel(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: object) -> None: ...

    def renderVertex(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: object) -> None: ...

    @overload
    def renderVertexLabel(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: ghidra.graph.viewer.VisualVertex) -> None: ...

    @overload
    def renderVertexLabel(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: object) -> None: ...

    def setEdgeLabelRenderer(self, __a0: edu.uci.ics.jung.visualization.renderers.Renderer.EdgeLabel) -> None: ...

    def setEdgeRenderer(self, __a0: edu.uci.ics.jung.visualization.renderers.Renderer.Edge) -> None: ...

    def setVertexLabelRenderer(self, __a0: edu.uci.ics.jung.visualization.renderers.Renderer.VertexLabel) -> None: ...

    def setVertexRenderer(self, __a0: edu.uci.ics.jung.visualization.renderers.Renderer.Vertex) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

