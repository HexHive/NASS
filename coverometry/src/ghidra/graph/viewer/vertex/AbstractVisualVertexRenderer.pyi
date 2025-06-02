import com.google.common.base
import edu.uci.ics.jung.algorithms.layout
import edu.uci.ics.jung.visualization
import edu.uci.ics.jung.visualization.renderers
import ghidra.graph.viewer
import java.awt
import java.lang


class AbstractVisualVertexRenderer(edu.uci.ics.jung.visualization.renderers.BasicVertexRenderer):
    """
    A base renderer class to define shared logic needed to render a vertex
    """





    def __init__(self): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getFullShape(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: ghidra.graph.viewer.VisualVertex) -> java.awt.Shape: ...

    def getVertexFillPaintTransformer(self) -> com.google.common.base.Function: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def paintVertex(self, __a0: edu.uci.ics.jung.visualization.RenderContext, __a1: edu.uci.ics.jung.algorithms.layout.Layout, __a2: object) -> None: ...

    def setVertexFillPaintTransformer(self, transformer: com.google.common.base.Function) -> None:
        """
        Sets the optional transformer used to convert a vertex into a color
        @param transformer the transformer
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
    def vertexFillPaintTransformer(self) -> com.google.common.base.Function: ...

    @vertexFillPaintTransformer.setter
    def vertexFillPaintTransformer(self, value: com.google.common.base.Function) -> None: ...