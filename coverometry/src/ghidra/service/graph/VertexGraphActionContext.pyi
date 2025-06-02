import docking
import ghidra.service.graph
import java.awt
import java.awt.event
import java.lang
import java.util


class VertexGraphActionContext(ghidra.service.graph.GraphActionContext):
    """
    GraphActionContext for when user invokes a popup action on a graph vertex.
    """





    def __init__(self, componentProvider: docking.ComponentProvider, graph: ghidra.service.graph.AttributedGraph, selectedVertices: java.util.Set, locatedVertex: ghidra.service.graph.AttributedVertex, clickedVertex: ghidra.service.graph.AttributedVertex): ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getClickedVertex(self) -> ghidra.service.graph.AttributedVertex:
        """
        Returns the vertex from where the popup menu was launched
        @return the vertex from where the popup menu was launched
        """
        ...

    def getComponentProvider(self) -> docking.ComponentProvider: ...

    def getContextObject(self) -> object: ...

    def getEventClickModifiers(self) -> int: ...

    def getFocusedVertex(self) -> ghidra.service.graph.AttributedVertex:
        """
        Returns the focused vertex (similar concept to the cursor in a text document)
        @return the focused vertex
        """
        ...

    def getGraph(self) -> ghidra.service.graph.AttributedGraph:
        """
        Returns the graph
        @return the graph
        """
        ...

    def getMouseEvent(self) -> java.awt.event.MouseEvent: ...

    def getSelectedVertices(self) -> java.util.Set:
        """
        Returns the set of selectedVertices in the graph
        @return the set of selectedVertices in the graph
        """
        ...

    def getSourceComponent(self) -> java.awt.Component: ...

    def getSourceObject(self) -> object: ...

    def hasAnyEventClickModifiers(self, modifiersMask: int) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setContextObject(self, contextObject: object) -> docking.DefaultActionContext: ...

    def setEventClickModifiers(self, modifiers: int) -> None: ...

    def setMouseEvent(self, e: java.awt.event.MouseEvent) -> docking.DefaultActionContext: ...

    def setSourceObject(self, sourceObject: object) -> docking.DefaultActionContext: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def clickedVertex(self) -> ghidra.service.graph.AttributedVertex: ...