import ghidra.app.nav
import ghidra.app.util.viewer.util
import ghidra.program.model.listing
import java.lang
import javax.swing


class OverviewProvider(object):
    """
    Interface implemented by classes that provide overview components to the right side of the
     listing.
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComponent(self) -> javax.swing.JComponent:
        """
        Returns the component to diplay in the right margin of the listing.
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setNavigatable(self, navigatable: ghidra.app.nav.Navigatable) -> None:
        """
        Set the component provider that this overview navigates
        @param navigatable the navigatable provider
        """
        ...

    def setProgram(self, program: ghidra.program.model.listing.Program, map: ghidra.app.util.viewer.util.AddressIndexMap) -> None:
        """
        Sets the current program and associated address-index map
        @param program the program to use.
        @param map the address-index map to use.
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
    def navigatable(self) -> None: ...  # No getter available.

    @navigatable.setter
    def navigatable(self, value: ghidra.app.nav.Navigatable) -> None: ...