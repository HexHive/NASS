from typing import List
import ghidra.service.graph
import java.awt
import java.lang


class VertexShape(object):
    """
    Class for defining shapes to use for rendering vertices in a graph
    """

    DIAMOND: ghidra.service.graph.VertexShape
    ELLIPSE: ghidra.service.graph.VertexShape
    HEXAGON: ghidra.service.graph.VertexShape
    OCTAGON: ghidra.service.graph.VertexShape
    PENTAGON: ghidra.service.graph.VertexShape
    RECTANGLE: ghidra.service.graph.VertexShape
    STAR: ghidra.service.graph.VertexShape
    TRIANGLE_DOWN: ghidra.service.graph.VertexShape
    TRIANGLE_UP: ghidra.service.graph.VertexShape







    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getLabelPosition(self) -> float:
        """
        Gets the relative amount of margin space to allocate above the label. The default is
         0.5 which will center the label in the associated shape. A value closer to 0 will move
         the label closer to the top and a value closer to 1 will move the label closer to the 
         bottom.
        @return the relative amount of margin space to allocate obove the label.s
        """
        ...

    def getMaxWidthToHeightRatio(self) -> int:
        """
        This is a factor to keep some shapes from being so distorted by very long labels that they
         effectively lose their shape when seen by the user
        @return the max width to height ratio
        """
        ...

    def getName(self) -> unicode:
        """
        Returns the name of the shape
        @return the name of the shape
        """
        ...

    @overload
    def getShape(self) -> java.awt.Shape:
        """
        Returns the {@link Shape} for this {@link VertexShape} instance
        @return the {@link Shape} for this {@link VertexShape} instance
        """
        ...

    @overload
    @staticmethod
    def getShape(shapeName: unicode) -> ghidra.service.graph.VertexShape:
        """
        Returns the {@link VertexShape} for the given shape name
        @param shapeName the name of the shape for which to get the {@link VertexShape}
        @return the {@link VertexShape} for the given shape name
        """
        ...

    @staticmethod
    def getShapeNames() -> List[unicode]:
        """
        Returns a list of names for all the supported {@link VertexShape}s
        @return a list of names for all the supported {@link VertexShape}s
        """
        ...

    def getShapeToLabelRatio(self) -> float:
        """
        Returns the size factor for a shape relative to its label. Shapes are sized based on the
         label of a vertex so that the label can fit inside the shape (mostly). Some subclasses
         will need to override this value to some value &gt; 1 to fit the label in the shape. For 
         example, a rectangle shape does not need to be extended because text naturally fits. But
         for a shape like a triangle, its bounding box needs to be bigger so that text doesn't
         "stick out" in the narrow part of the triangle.
        @return the size factor for a shape relatvie to its label
        """
        ...

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

    @property
    def labelPosition(self) -> float: ...

    @property
    def maxWidthToHeightRatio(self) -> int: ...

    @property
    def name(self) -> unicode: ...

    @property
    def shape(self) -> java.awt.Shape: ...

    @property
    def shapeToLabelRatio(self) -> float: ...