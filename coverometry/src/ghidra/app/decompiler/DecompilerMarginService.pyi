import ghidra.app.decompiler.component
import ghidra.app.decompiler.component.margin
import java.lang


class DecompilerMarginService(object):
    """
    A service that allows clients to add custom margins in the Decompiler UI.
    """









    def addMarginProvider(self, provider: ghidra.app.decompiler.component.margin.DecompilerMarginProvider) -> None:
        """
        Add a margin to the Decompiler's primary window
        @param provider the margin provider
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getDecompilerPanel(self) -> ghidra.app.decompiler.component.DecompilerPanel:
        """
        Get the panel associated with this margin
        @return the panel
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeMarginProvider(self, provider: ghidra.app.decompiler.component.margin.DecompilerMarginProvider) -> None:
        """
        Remove a margin from the Decompiler's primary window
        @param provider the margin provider
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
    def decompilerPanel(self) -> ghidra.app.decompiler.component.DecompilerPanel: ...