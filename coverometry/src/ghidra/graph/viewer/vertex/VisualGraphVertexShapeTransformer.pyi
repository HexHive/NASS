import com.google.common.base
import ghidra.graph.viewer
import java.awt
import java.lang
import java.util.function


class VisualGraphVertexShapeTransformer(object, com.google.common.base.Function):
    """
    The default VisualGraph renderer.  By default, the shape returned by this class is
     a Rectangle of the given vertex's VisualVertex#getComponent().
 
     This class is aware of VertexShapeProviders, which allows vertex creators to 
     provide vertex shapes that differ for rendering and clicking.  See that class for more info.
    """





    def __init__(self): ...



    def andThen(self, __a0: java.util.function.Function) -> java.util.function.Function: ...

    @overload
    def apply(self, __a0: ghidra.graph.viewer.VisualVertex) -> java.awt.Shape: ...

    @overload
    def apply(self, __a0: object) -> object: ...

    def compose(self, __a0: java.util.function.Function) -> java.util.function.Function: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    @staticmethod
    def identity() -> java.util.function.Function: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    def transformToCompactShape(self, __a0: ghidra.graph.viewer.VisualVertex) -> java.awt.Shape: ...

    def transformToFullShape(self, __a0: ghidra.graph.viewer.VisualVertex) -> java.awt.Shape: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

