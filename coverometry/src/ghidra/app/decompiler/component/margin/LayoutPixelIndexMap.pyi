import java.lang


class LayoutPixelIndexMap(object):
    """
    A mapping from pixel coordinate to layout index
 
 
     At the moment, the only implementation provides a map from vertical position to layout. While
     this does not have to be the case, the documentation will presume the y coordinate.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getIndex(self, pixel: int) -> long:
        """
        Get the index of the layout at the given position
 
         <p>
         Get the index of the layout occupying the line of pixels in the main panel having the given y
         coordinate. In essence, this maps from vertical position, relative to the main panel's
         viewport, to layout index. This accounts for scrolling and non-uniform height among the
         layouts.
        @implNote Clients should avoid frequent calls to this method. Even though it can be
                   implemented easily in log time, an invocation for every pixel or line of pixels
                   painted could still be unnecessarily expensive. It should only be necessary to call
                   this once or twice per repaint. See
                   {@link DecompilerMarginProvider#setProgram(Program, LayoutModel, LayoutPixelIndexMap)}.
        @param pixel the vertical position of the pixel, relative to the main panel's viewport
        @return the index of the layout
        """
        ...

    def getPixel(self, index: long) -> int:
        """
        Get the top of the layout with the given index
 
         <p>
         Gets the minimum y coordinate of any pixel occupied by the layout having the given index. In
         essence, this maps from layout index to vertical position, relative to the main panel's
         viewport. This accounts for scrolling and non-uniform height among the layouts.
        @param index the index of the layout
        @return the top of the layout, relative to the main panel's viewport
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

