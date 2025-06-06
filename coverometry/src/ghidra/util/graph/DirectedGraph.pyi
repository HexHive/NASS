from typing import List
import ghidra.util.graph
import ghidra.util.graph.attributes
import java.lang
import java.util


class DirectedGraph(object):
    """
    Base implementation of a directed graph. A directed graph consists
     of a set of vertices (implemented as a VertexSet) and a set of edges
     (implemented as an EdgeSet) joining ordered pairs of vertices in the
     graph. Both vertices and edges can belong to more than one DirectedGraph.
     Attributes for both vertices and edges may be defined for a DirectedGraph.
     Parallel edges (more than one edge with the same from and to vertices)
     are allowed in DirectedGraph. Loops are also allowed.
    """





    @overload
    def __init__(self):
        """
        Default constructor
        """
        ...

    @overload
    def __init__(self, vertexCapacity: int, edgeCapacity: int):
        """
        Creates an empty DirectedGraph with room for 
         vertexCapacity vertices and edgeCapacity edges.
        """
        ...



    @overload
    def add(self, e: ghidra.util.graph.Edge) -> bool:
        """
        Adds the specified edge to the graph. If either endpoint of the
         edge is not in the graph that vertex is also added to the graph.
        """
        ...

    @overload
    def add(self, v: ghidra.util.graph.Vertex) -> bool:
        """
        Adds the specified vertex to the graph.
        """
        ...

    def areRelatedAs(self, parent: ghidra.util.graph.Vertex, child: ghidra.util.graph.Vertex) -> bool:
        """
        Returns true iff the graph contains and edge from the parent vertex
         to the child vertex.
        """
        ...

    def assignVerticesToStrongComponents(self) -> java.util.Set:
        """
        Returns an array of Sets (HashSet). Each set contains the vertices
          within a single strongly connected component of the DirectedGraph.
 
         A strongly connected component of a directed graph is a subgraph 
         in which it is possible to find a directed path from any vertex to any 
         other vertex in the graph. A cycle is a simple example of strongly 
         connected graph.
        """
        ...

    def clear(self) -> None:
        """
        Removes all vertices and edges from the graph without changing 
         the space allocated.
        """
        ...

    def complexityDepth(self) -> ghidra.util.graph.attributes.IntegerAttribute:
        """
        Assigns levels to the graph in a bottom up fashion. All sinks have the
          same level.
        """
        ...

    @overload
    def contains(self, e: ghidra.util.graph.Edge) -> bool:
        """
        Returns true iff the graph contains the edge e.
        """
        ...

    @overload
    def contains(self, v: ghidra.util.graph.Vertex) -> bool:
        """
        Returns true iff the vertex is in the graph.
        """
        ...

    def containsAsSubgraph(self, g: ghidra.util.graph.DirectedGraph) -> bool:
        """
        Returns true iff all nodes and edges of the given graph are in the current graph
        """
        ...

    def copy(self) -> ghidra.util.graph.DirectedGraph:
        """
        @return A directed graph with the same vertices, edges, and attributes.
        """
        ...

    def degree(self, v: ghidra.util.graph.Vertex) -> float:
        """
        Returns valence as a double. Should be overridden extending classes.
        """
        ...

    def descendantsGraph(self, seeds: List[ghidra.util.graph.Vertex]) -> ghidra.util.graph.DirectedGraph:
        """
        Get the graph induced by the seed vertices and their descendants
        """
        ...

    def edgeAttributes(self) -> ghidra.util.graph.attributes.AttributeManager:
        """
        Returns the AttributeManager for the edges of this graph.
        """
        ...

    def edgeIterator(self) -> ghidra.util.graph.GraphIterator:
        """
        Returns an iterator for the EdgeSet of this graph.
        """
        ...

    def edges(self) -> ghidra.util.graph.EdgeSet:
        """
        Returns the EdgeSet of this graph.
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getAncestors(self, v: ghidra.util.graph.Vertex) -> java.util.Set:
        """
        Returns a set of all the vertices which are ancestors of the given vertex.
           Note: By definition a vertex is one of its own ancestors.
        """
        ...

    @overload
    def getChildren(self, v: ghidra.util.graph.Vertex) -> java.util.Set:
        """
        Returns a Set (HashSet) containing all vertices that are the tos
           of outgoing edges of the given vertex. Note in the case of multiple
          edges, the number of children and outvalence need not be the same.
        """
        ...

    @overload
    def getChildren(self, vs: java.util.Set) -> java.util.Set:
        """
        Returns all children of the vertices in the given set.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getComponentContaining(self, v: ghidra.util.graph.Vertex) -> ghidra.util.graph.DirectedGraph:
        """
        Returns the subgraph of this graph which is the component containing v.
        """
        ...

    def getComponents(self) -> List[ghidra.util.graph.DirectedGraph]:
        """
        Returns an array of directed graphs. Each array element is a 
         DirectedGraph consisting of a single
         connected component of this graph.
        """
        ...

    @overload
    def getDescendants(self, seedVertices: List[ghidra.util.graph.Vertex]) -> java.util.Set:
        """
        Returns a Set (HashSet) of all vertices descended from a vertex in the
          given array.
        """
        ...

    @overload
    def getDescendants(self, v: ghidra.util.graph.Vertex) -> java.util.Set:
        """
        Returns a Set (HashSet) containing all descendants of the given vertex.
          Note: The vertex is defined to be a descendant of itself.
        """
        ...

    def getEdgeArray(self) -> List[ghidra.util.graph.Edge]:
        """
        returns an array containing the edges in the graph
        """
        ...

    def getEdgeWithKey(self, key: long) -> ghidra.util.graph.Edge:
        """
        @param key
        @return the edge in the graph with the specified key or null
         if the graph does not contain an edge with the key.
        """
        ...

    @overload
    def getEdges(self) -> java.util.Set:
        """
        returns a java.util.Set containing the edges in this graph.
        """
        ...

    @overload
    def getEdges(self, from_: ghidra.util.graph.Vertex, to: ghidra.util.graph.Vertex) -> List[ghidra.util.graph.Edge]:
        """
        Returns all edges joing the from and to vertices. Recall DirectedGraph
         uses a multigraph model where parallel edges are allowed.
        """
        ...

    def getEntryPoints(self) -> java.util.Vector:
        """
        Returns a vector containing the entry points to a directed graph. An entry
          point is either a source (in valence zero) or the least vertex in a strongly
          connected component unreachable from any vertex outside the strongly
          connected component. Least is defined here to be the vertex with the smallest
          key.
        """
        ...

    def getIncomingEdges(self, v: ghidra.util.graph.Vertex) -> java.util.Set:
        """
        Returns a Set containing all of the edges to the given vertex.
        """
        ...

    def getLevels(self) -> ghidra.util.graph.attributes.IntegerAttribute:
        """
        This method assigns levels in a top-down manner. Sources are on level 0.
        """
        ...

    @overload
    def getNeighborhood(self, v: ghidra.util.graph.Vertex) -> java.util.Set:
        """
        Returns a java.util.Set containing the vertex v and its neighbors.
        """
        ...

    @overload
    def getNeighborhood(self, vs: java.util.Set) -> java.util.Set:
        """
        Returns a java.util.Set containing the vertices in the given Set and their
          neighbors.
        """
        ...

    def getOutgoingEdges(self, v: ghidra.util.graph.Vertex) -> java.util.Set:
        """
        Returns the outgoing edges from the given vertex.
        """
        ...

    @overload
    def getParents(self, v: ghidra.util.graph.Vertex) -> java.util.Set:
        """
        Returns a Set containg all of the vertices from which an edge comes
          into the given vertex.
        """
        ...

    @overload
    def getParents(self, vs: java.util.Set) -> java.util.Set:
        """
        Returns all parents of the vertices in the given set.
        """
        ...

    def getReferent(self, v: ghidra.util.graph.Vertex) -> object:
        """
        Returns the referent of the object used to create v if it exists. If the
          vertex was created with a null referent this method returns null.
        """
        ...

    def getSinks(self) -> List[ghidra.util.graph.Vertex]:
        """
        Returns a Vertex[] containing the sinks. A vertex is a sink if it 
         has no outgoing edges.
        """
        ...

    def getSources(self) -> List[ghidra.util.graph.Vertex]:
        """
        Returns a Vertex[] containing the sources. A vertex is a source if
         it has no incoming edges.
        """
        ...

    def getVertexArray(self) -> List[ghidra.util.graph.Vertex]:
        """
        returns an array containing the vertices in the graph
        """
        ...

    def getVertexWithKey(self, key: long) -> ghidra.util.graph.Vertex:
        """
        @param key
        @return the vertex in the graph with the specified key or null
         if the graph does not contain an vertex with the key.
        """
        ...

    def getVertices(self) -> java.util.Set:
        """
        returns a java.util.Set containing the vertices in this graph.
        """
        ...

    def getVerticesHavingReferent(self, o: object) -> List[ghidra.util.graph.Vertex]:
        """
        Returns Vertex[] containing all vertices having the given object as
          a referent. Any number of vertices in the graph may refer back to 
         the same object.
        """
        ...

    def getVerticesInContainingComponent(self, v: ghidra.util.graph.Vertex) -> java.util.Set:
        """
        Returns a java.util.Set containing all of the vertices within the
          same component a the given vertex.
        """
        ...

    def hashCode(self) -> int: ...

    def inDegree(self, v: ghidra.util.graph.Vertex) -> float:
        """
        Returns inValence as a double. Should be overridden extending classes.
        """
        ...

    def inValence(self, v: ghidra.util.graph.Vertex) -> int:
        """
        The number of edges having v as their terminal or
          "to" vertex.
        """
        ...

    def incomingEdges(self, v: ghidra.util.graph.Vertex) -> List[ghidra.util.graph.Edge]:
        """
        Returns an array of all incoming edges.
        """
        ...

    def inducedSubgraph(self, vertexSet: List[ghidra.util.graph.Vertex]) -> ghidra.util.graph.DirectedGraph:
        """
        Returns the directed graph which is subgraph induced by the given
          set of vertices. The vertex set of the returned graph contains the
          given vertices which belong to this graph. An edge of this graph
          is in the returned graph iff both endpoints belong to the given vertices.
        """
        ...

    def intersectionWith(self, otherGraph: ghidra.util.graph.DirectedGraph) -> None:
        """
        Creates intersection of graphs in place by adding all vertices and edges of
         other graph to this graph. This method used to return a different graph
         as the intersection but now does not.
        """
        ...

    def join(self, other: ghidra.util.graph.DirectedGraph) -> ghidra.util.graph.DirectedGraph:
        """
        This method joins nodes from a directed graph into this.  This 
         allows DirectedGraph subclasses to copy nodes and attributes, 
         a shortcomings with the unionWith method.
        @param other the other directed graph that is to be joined into this one.
        @return this directed graph
        """
        ...

    def loopDegree(self, v: ghidra.util.graph.Vertex) -> float:
        """
        Returns numLoops as a double. Should be overridden extending classes.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def numEdges(self) -> int:
        """
        Returns the number of edges in the graph
        """
        ...

    def numLoops(self, v: ghidra.util.graph.Vertex) -> int:
        """
        The number of edges having v as both their terminal and
          terminal vertex.
        """
        ...

    def numSinks(self) -> int:
        """
        returns the number of vertices with outValence zero.
        """
        ...

    def numSources(self) -> int:
        """
        returns the number of vertices with inValence zero.
        """
        ...

    def numVertices(self) -> int:
        """
        Returns the number of vertices in the graph
        """
        ...

    def outDegree(self, v: ghidra.util.graph.Vertex) -> float:
        """
        Returns outValence as a double. Should be overridden extending classes.
        """
        ...

    def outValence(self, v: ghidra.util.graph.Vertex) -> int:
        """
        The number of edges having v as their initial or
          "from" vertex.
        """
        ...

    def outgoingEdges(self, v: ghidra.util.graph.Vertex) -> List[ghidra.util.graph.Edge]:
        """
        Returns an array of all outgoing edges.
        """
        ...

    @overload
    def remove(self, e: ghidra.util.graph.Edge) -> bool:
        """
        Removes Edge e from the graph. No effect if the edge is not in the graph.
        """
        ...

    @overload
    def remove(self, v: ghidra.util.graph.Vertex) -> bool:
        """
        Removes the vertex v from the graph. Also removes all edges incident with
         v. Does nothing if the vertex is not in the graph.
        """
        ...

    def selfEdges(self, v: ghidra.util.graph.Vertex) -> List[ghidra.util.graph.Edge]:
        """
        Returns an array of all edges with the given vertex as both the from
           and to.
        """
        ...

    def toString(self) -> unicode: ...

    def unionWith(self, otherGraph: ghidra.util.graph.DirectedGraph) -> None:
        """
        Creates union of graphs in place by adding all vertices and edges of
         other graph to this graph. This method used to return a different graph
         as the union but now does not.
        """
        ...

    def valence(self, v: ghidra.util.graph.Vertex) -> int:
        """
        The number of edges incident with v. For unweighted
           graphs valence and degree are the same, except valence is an int
          while degree is a double.
        """
        ...

    def vertexAttributes(self) -> ghidra.util.graph.attributes.AttributeManager:
        """
        Returns the AttributeManager for the vertices of this graph.
        """
        ...

    def vertexIterator(self) -> ghidra.util.graph.GraphIterator:
        """
        Returns an iterator for the VertexSet of this graph.
        """
        ...

    def vertices(self) -> ghidra.util.graph.VertexSet:
        """
        Returns the VertexSet of this graph.
        """
        ...

    def verticesUnreachableFromSources(self) -> List[ghidra.util.graph.Vertex]:
        """
        Returns array of all vertices unreachable from a source. These are the
           vertices descending only from a non-trivial strongly connected component.
        """
        ...

    @staticmethod
    def verts2referentSet(verts: java.util.Collection) -> java.util.Set:
        """
        This method converts a collection of verticies into a set of its
         referent objects.  It is up to the methods using the created set 
         to properly type cast the set's elements.
        @param verts the vertices
        @return the set of referent objects
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def components(self) -> List[ghidra.util.graph.DirectedGraph]: ...

    @property
    def edgeArray(self) -> List[ghidra.util.graph.Edge]: ...

    @property
    def entryPoints(self) -> java.util.Vector: ...

    @property
    def levels(self) -> ghidra.util.graph.attributes.IntegerAttribute: ...

    @property
    def sinks(self) -> List[ghidra.util.graph.Vertex]: ...

    @property
    def sources(self) -> List[ghidra.util.graph.Vertex]: ...

    @property
    def vertexArray(self) -> List[ghidra.util.graph.Vertex]: ...