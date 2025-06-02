import com.google.common.base
import ghidra.app.plugin.core.functiongraph.graph.vertex
import java.awt
import java.lang
import java.util.function


class FGVertexPickableBackgroundPaintTransformer(object, com.google.common.base.Function):




    def __init__(self, __a0: edu.uci.ics.jung.visualization.picking.PickedInfo, __a1: java.awt.Color, __a2: java.awt.Color, __a3: java.awt.Color): ...



    def andThen(self, __a0: java.util.function.Function) -> java.util.function.Function: ...

    @overload
    def apply(self, __a0: ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex) -> java.awt.Paint: ...

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

