import ghidra.app.plugin.core.functiongraph.mvc
import ghidra.graph
import ghidra.graph.viewer
import ghidra.graph.viewer.event.mouse
import ghidra.graph.viewer.layout
import ghidra.graph.viewer.vertex
import java.awt
import java.awt.event
import java.lang
import java.util
import javax.swing


class FGView(ghidra.graph.viewer.VisualGraphView):




    def __init__(self, __a0: ghidra.app.plugin.core.functiongraph.mvc.FGController, __a1: javax.swing.JComponent): ...



    def arePopupsEnabled(self) -> bool: ...

    def broadcastLayoutRefreshNeeded(self) -> None: ...

    def cleanup(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def generateGraphPerspective(self) -> ghidra.graph.viewer.GraphPerspectiveInfo: ...

    def getClass(self) -> java.lang.Class: ...

    def getController(self) -> ghidra.app.plugin.core.functiongraph.mvc.FGController: ...

    def getFocusedVertex(self) -> ghidra.graph.viewer.VisualVertex: ...

    def getGraphComponent(self) -> ghidra.graph.viewer.GraphComponent: ...

    def getLayoutProvider(self) -> ghidra.graph.viewer.layout.LayoutProvider: ...

    def getPrimaryGraphViewer(self) -> ghidra.graph.viewer.GraphViewer: ...

    def getSatelliteViewer(self) -> ghidra.graph.viewer.SatelliteGraphViewer: ...

    def getSelectedVertices(self) -> java.util.Set: ...

    def getUndockedSatelliteComponent(self) -> javax.swing.JComponent: ...

    def getVertexFocusPathHighlightMode(self) -> ghidra.graph.viewer.PathHighlightMode: ...

    def getVertexHoverPathHighlightMode(self) -> ghidra.graph.viewer.PathHighlightMode: ...

    def getVertexPointInViewSpace(self, __a0: ghidra.graph.viewer.VisualVertex) -> java.awt.Point: ...

    def getViewComponent(self) -> javax.swing.JComponent: ...

    def getViewUpdater(self) -> ghidra.graph.viewer.VisualGraphViewUpdater: ...

    def getVisualGraph(self) -> ghidra.graph.VisualGraph: ...

    def hashCode(self) -> int: ...

    def isGraphViewStale(self) -> bool: ...

    def isSatelliteComponent(self, __a0: java.awt.Component) -> bool: ...

    def isSatelliteDocked(self) -> bool: ...

    def isSatelliteVisible(self) -> bool: ...

    def isScaledPastInteractionThreshold(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def optionsChanged(self) -> None: ...

    def repaint(self) -> None: ...

    def requestFocus(self) -> None: ...

    def setGraph(self, __a0: ghidra.graph.VisualGraph) -> None: ...

    def setGraphPerspective(self, __a0: ghidra.graph.viewer.GraphPerspectiveInfo) -> None: ...

    def setLayoutProvider(self, __a0: ghidra.graph.viewer.layout.LayoutProvider) -> None: ...

    def setPopupsVisible(self, __a0: bool) -> None: ...

    def setSatelliteDocked(self, __a0: bool) -> None: ...

    def setSatelliteListener(self, __a0: ghidra.graph.viewer.GraphSatelliteListener) -> None: ...

    def setSatelliteVisible(self, __a0: bool) -> None: ...

    def setStatusMessage(self, __a0: unicode) -> None: ...

    def setTooltipProvider(self, __a0: ghidra.graph.viewer.event.mouse.VertexTooltipProvider) -> None: ...

    def setVertexClickListener(self, __a0: ghidra.graph.viewer.vertex.VertexClickListener) -> None: ...

    def setVertexFocusListener(self, __a0: ghidra.graph.viewer.vertex.VertexFocusListener) -> None: ...

    def setVertexFocusPathHighlightMode(self, __a0: ghidra.graph.viewer.PathHighlightMode) -> None: ...

    def setVertexHoverPathHighlightMode(self, __a0: ghidra.graph.viewer.PathHighlightMode) -> None: ...

    def showErrorView(self, __a0: unicode) -> None: ...

    def toString(self) -> unicode: ...

    def translateMouseEventFromVertexToViewSpace(self, __a0: ghidra.graph.viewer.VisualVertex, __a1: java.awt.event.MouseEvent) -> java.awt.event.MouseEvent: ...

    def translatePointFromVertexToViewSpace(self, __a0: ghidra.graph.viewer.VisualVertex, __a1: java.awt.Point) -> java.awt.Point: ...

    def translateRectangleFromVertexToViewSpace(self, __a0: ghidra.graph.viewer.VisualVertex, __a1: java.awt.Rectangle) -> java.awt.Rectangle: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def zoomInGraph(self) -> None: ...

    def zoomOutGraph(self) -> None: ...

    def zoomToVertex(self, __a0: ghidra.graph.viewer.VisualVertex) -> None: ...

    def zoomToWindow(self) -> None: ...

    @property
    def controller(self) -> ghidra.app.plugin.core.functiongraph.mvc.FGController: ...

    @property
    def graphViewStale(self) -> bool: ...

    @property
    def layoutProvider(self) -> ghidra.graph.viewer.layout.LayoutProvider: ...

    @layoutProvider.setter
    def layoutProvider(self, value: ghidra.graph.viewer.layout.LayoutProvider) -> None: ...

    @property
    def viewUpdater(self) -> ghidra.graph.viewer.FGViewUpdater: ...