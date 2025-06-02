import docking.action
import docking.widgets
import ghidra.service.graph
import ghidra.util.task
import java.lang
import java.util


class GraphDisplay(object):
    """
    Interface for objects that display (or consume) graphs.  Normally, a graph display represents
     a visual component for displaying and interacting with a graph.  Some implementation may not
     be a visual component, but instead consumes/processes the graph (i.e. graph exporter). In this
     case, there is no interactive element and once the graph has been set on the display, it is
     closed.
    """









    def addAction(self, action: docking.action.DockingActionIf) -> None:
        """
        Adds the action to the graph display. Not all GraphDisplays support adding custom
         actions, so this may have no effect.
        @param action the action to add
        """
        ...

    def clear(self) -> None:
        """
        Clears all graph vertices and edges from this graph display
        """
        ...

    def close(self) -> None:
        """
        Closes this graph display window.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getActions(self) -> java.util.Collection:
        """
        Gets all actions that have been added to this graph display.  If this display does not
         support actions, then an empty collection will be returned.
        @return the actions
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getFocusedVertex(self) -> ghidra.service.graph.AttributedVertex:
        """
        Returns the currently focused vertex or null if no vertex is focused
        @return the currently focused vertex or null if no vertex is focused
        """
        ...

    def getGraph(self) -> ghidra.service.graph.AttributedGraph:
        """
        Returns the graph for this display
        @return the graph for this display
        """
        ...

    def getGraphTitle(self) -> unicode:
        """
        Returns the title of the current graph
        @return the title of the current graph
        """
        ...

    def getSelectedVertices(self) -> java.util.Set:
        """
        Returns a set of vertex ids for all the currently selected vertices
        @return a set of vertex ids for all the currently selected vertices
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def selectVertices(self, vertexSet: java.util.Set, eventTrigger: docking.widgets.EventTrigger) -> None:
        """
        Tells the graph display window to select the vertices with the given ids
        @param vertexSet the set of vertices to select
        @param eventTrigger Provides a hint to the GraphDisplay as to why we are updating the
         graph location so that the GraphDisplay can decide if it should send out a notification via
         the {@link GraphDisplayListener#selectionChanged(Set)}. For example, if we are updating
         the the location due to an event from the main application, we don't want to notify the
         application the graph changed to avoid event cycles. See {@link EventTrigger} for more
         information.
        """
        ...

    def setFocusedVertex(self, vertex: ghidra.service.graph.AttributedVertex, eventTrigger: docking.widgets.EventTrigger) -> None:
        """
        Tells the graph display window to focus the vertex with the given id
        @param vertex the vertex to focus
        @param eventTrigger Provides a hint to the GraphDisplay as to why we are updating the
         graph location so that the GraphDisplay can decide if it should send out a notification via
         the {@link GraphDisplayListener#locationFocusChanged(AttributedVertex)}. For example, if we
         are updating the the location due to an event from the main application, we don't want to
         notify the application the graph changed to avoid event cycles. See {@link EventTrigger} for
         more information.
        """
        ...

    @overload
    def setGraph(self, graph: ghidra.service.graph.AttributedGraph, title: unicode, append: bool, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Sets the graph to be displayed or consumed by this graph display
        @param graph the graph to display or consume
        @param title a title for the graph
        @param monitor a {@link TaskMonitor} which can be used to cancel the graphing operation
        @param append if true, append the new graph to any existing graph
        @throws CancelledException thrown if the graphing operation was cancelled
        @deprecated You should now use the form that takes in a {@link GraphDisplayOptions}
        """
        ...

    @overload
    def setGraph(self, graph: ghidra.service.graph.AttributedGraph, options: ghidra.service.graph.GraphDisplayOptions, title: unicode, append: bool, monitor: ghidra.util.task.TaskMonitor) -> None:
        """
        Sets the graph to be displayed or consumed by this graph display
        @param graph the graph to display or consume
        @param options {@link GraphDisplayOptions} for configuring how the display will
         render vertices and edges based on there vertex type and edge type respectively.
        @param title a title for the graph
        @param monitor a {@link TaskMonitor} which can be used to cancel the graphing operation
        @param append if true, append the new graph to any existing graph
        @throws CancelledException thrown if the graphing operation was cancelled
        """
        ...

    def setGraphDisplayListener(self, listener: ghidra.service.graph.GraphDisplayListener) -> None:
        """
        Sets a {@link GraphDisplayListener} to be notified when the user changes the vertex focus
         or selects one or more nodes in a graph window
        @param listener the listener to be notified
        """
        ...

    def toString(self) -> unicode: ...

    def updateVertexName(self, vertex: ghidra.service.graph.AttributedVertex, newName: unicode) -> None:
        """
        Updates a vertex to a new name
        @param vertex the vertex to rename
        @param newName the new name for the vertex
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def actions(self) -> java.util.Collection: ...

    @property
    def focusedVertex(self) -> ghidra.service.graph.AttributedVertex: ...

    @property
    def graph(self) -> ghidra.service.graph.AttributedGraph: ...

    @property
    def graphDisplayListener(self) -> None: ...  # No getter available.

    @graphDisplayListener.setter
    def graphDisplayListener(self, value: ghidra.service.graph.GraphDisplayListener) -> None: ...

    @property
    def graphTitle(self) -> unicode: ...

    @property
    def selectedVertices(self) -> java.util.Set: ...