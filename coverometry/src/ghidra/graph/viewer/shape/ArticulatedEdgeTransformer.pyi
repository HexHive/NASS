import com.google.common.base
import ghidra.graph.viewer
import java.awt
import java.lang
import java.util.function


class ArticulatedEdgeTransformer(object, com.google.common.base.Function):
    """
    An edge shape that renders as a series of straight lines between articulation points.
    """





    def __init__(self): ...



    def andThen(self, __a0: java.util.function.Function) -> java.util.function.Function: ...

    @overload
    def apply(self, __a0: ghidra.graph.viewer.VisualEdge) -> java.awt.Shape: ...

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

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

