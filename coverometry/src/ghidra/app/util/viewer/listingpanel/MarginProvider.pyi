import ghidra.app.util.viewer.listingpanel
import ghidra.app.util.viewer.util
import ghidra.program.model.listing
import ghidra.program.util
import java.lang
import javax.swing


class MarginProvider(object):
    """
    Interface for objects that want to add a component to the listing's left margin.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self) -> javax.swing.JComponent:
        """
        Get the component to show the margin markers.
        """
        ...

    def getMarkerLocation(self, x: int, y: int) -> ghidra.program.util.MarkerLocation:
        """
        Get the marker location for the given x, y point.
        @param x the horizontal coordinate.
        @param y the vertical coordinate.
        """
        ...

    def hashCode(self) -> int: ...

    def isResizeable(self) -> bool:
        """
        Return whether the component can be resized.
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setProgram(self, program: ghidra.program.model.listing.Program, addressIndexMap: ghidra.app.util.viewer.util.AddressIndexMap, pixelMap: ghidra.app.util.viewer.listingpanel.VerticalPixelAddressMap) -> None:
        """
        Set the program and associated maps.
        @param program the program to use.
        @param addressIndexMap the address-index map to use.
        @param pixelMap the vertical pixel map to use.
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def component(self) -> javax.swing.JComponent: ...

    @property
    def resizeable(self) -> bool: ...