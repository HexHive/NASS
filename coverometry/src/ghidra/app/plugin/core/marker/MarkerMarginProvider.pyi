import ghidra.app.util.viewer.listingpanel
import ghidra.app.util.viewer.util
import ghidra.program.model.listing
import ghidra.program.util
import java.lang
import javax.swing


class MarkerMarginProvider(object, ghidra.app.util.viewer.listingpanel.MarginProvider):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self) -> javax.swing.JComponent: ...

    def getMarkerLocation(self, __a0: int, __a1: int) -> ghidra.program.util.MarkerLocation: ...

    def hashCode(self) -> int: ...

    def isResizeable(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setProgram(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.app.util.viewer.util.AddressIndexMap, __a2: ghidra.app.util.viewer.listingpanel.VerticalPixelAddressMap) -> None: ...

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