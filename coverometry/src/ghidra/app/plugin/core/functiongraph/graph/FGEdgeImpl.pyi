from typing import List
import ghidra.app.plugin.core.functiongraph.graph
import ghidra.app.plugin.core.functiongraph.graph.vertex
import ghidra.graph.viewer
import ghidra.program.model.symbol
import java.lang


class FGEdgeImpl(object, ghidra.app.plugin.core.functiongraph.graph.FGEdge):




    def __init__(self, __a0: ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex, __a1: ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex, __a2: ghidra.program.model.symbol.FlowType, __a3: ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions): ...



    @overload
    def cloneEdge(self, __a0: ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex, __a1: ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex) -> ghidra.app.plugin.core.functiongraph.graph.FGEdge: ...

    @overload
    def cloneEdge(self, __a0: ghidra.graph.viewer.VisualVertex, __a1: ghidra.graph.viewer.VisualVertex) -> ghidra.graph.viewer.VisualEdge: ...

    def equals(self, __a0: object) -> bool: ...

    def getAlpha(self) -> float: ...

    def getArticulationPoints(self) -> List[object]: ...

    def getClass(self) -> java.lang.Class: ...

    def getDefaultAlpha(self) -> float: ...

    def getEmphasis(self) -> float: ...

    def getEnd(self) -> object: ...

    def getFlowType(self) -> ghidra.program.model.symbol.FlowType: ...

    def getLabel(self) -> unicode: ...

    def getStart(self) -> object: ...

    def hashCode(self) -> int: ...

    def isInFocusedVertexPath(self) -> bool: ...

    def isInHoveredVertexPath(self) -> bool: ...

    def isSelected(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setAlpha(self, __a0: float) -> None: ...

    def setArticulationPoints(self, __a0: List[object]) -> None: ...

    def setDefaultAlpha(self, __a0: float) -> None: ...

    def setEmphasis(self, __a0: float) -> None: ...

    def setInFocusedVertexPath(self, __a0: bool) -> None: ...

    def setInHoveredVertexPath(self, __a0: bool) -> None: ...

    def setLabel(self, __a0: unicode) -> None: ...

    def setSelected(self, __a0: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def alpha(self) -> float: ...

    @alpha.setter
    def alpha(self, value: float) -> None: ...

    @property
    def articulationPoints(self) -> List[object]: ...

    @articulationPoints.setter
    def articulationPoints(self, value: List[object]) -> None: ...

    @property
    def defaultAlpha(self) -> float: ...

    @defaultAlpha.setter
    def defaultAlpha(self, value: float) -> None: ...

    @property
    def emphasis(self) -> float: ...

    @emphasis.setter
    def emphasis(self, value: float) -> None: ...

    @property
    def end(self) -> ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex: ...

    @property
    def flowType(self) -> ghidra.program.model.symbol.FlowType: ...

    @property
    def inFocusedVertexPath(self) -> bool: ...

    @inFocusedVertexPath.setter
    def inFocusedVertexPath(self, value: bool) -> None: ...

    @property
    def inHoveredVertexPath(self) -> bool: ...

    @inHoveredVertexPath.setter
    def inHoveredVertexPath(self, value: bool) -> None: ...

    @property
    def label(self) -> unicode: ...

    @label.setter
    def label(self, value: unicode) -> None: ...

    @property
    def selected(self) -> bool: ...

    @selected.setter
    def selected(self, value: bool) -> None: ...

    @property
    def start(self) -> ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex: ...