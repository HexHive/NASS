import ghidra.app.nav
import ghidra.app.util.viewer.listingpanel
import ghidra.app.util.viewer.util
import ghidra.program.model.listing
import java.lang
import javax.swing


class MarkerOverviewProvider(object, ghidra.app.util.viewer.listingpanel.OverviewProvider):








    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self) -> javax.swing.JComponent: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def repaintPanel(self) -> None: ...

    def setNavigatable(self, __a0: ghidra.app.nav.Navigatable) -> None: ...

    def setProgram(self, __a0: ghidra.program.model.listing.Program, __a1: ghidra.app.util.viewer.util.AddressIndexMap) -> None: ...

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
    def navigatable(self) -> None: ...  # No getter available.

    @navigatable.setter
    def navigatable(self, value: ghidra.app.nav.Navigatable) -> None: ...