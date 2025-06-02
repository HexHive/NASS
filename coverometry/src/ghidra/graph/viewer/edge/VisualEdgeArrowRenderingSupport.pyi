import edu.uci.ics.jung.visualization
import java.awt
import java.awt.geom
import java.lang


class VisualEdgeArrowRenderingSupport(object):
    """
    Basic class to calculate the position of an edge arrow
    """





    def __init__(self): ...



    def createArrowTransform(self, rc: edu.uci.ics.jung.visualization.RenderContext, edgeShape: java.awt.Shape, vertexShape: java.awt.Shape) -> java.awt.geom.AffineTransform: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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

