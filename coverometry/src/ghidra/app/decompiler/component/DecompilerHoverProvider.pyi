import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.support
import ghidra.app.decompiler.component.hover
import ghidra.app.plugin.core.hover
import ghidra.program.model.listing
import java.awt
import java.awt.event
import java.lang


class DecompilerHoverProvider(ghidra.app.plugin.core.hover.AbstractHoverProvider):




    def __init__(self): ...



    def addHoverService(self, hoverService: ghidra.app.decompiler.component.hover.DecompilerHoverService) -> None: ...

    def closeHover(self) -> None: ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def hashCode(self) -> int: ...

    def initializeListingHoverHandler(self, __a0: ghidra.app.plugin.core.hover.AbstractHoverProvider) -> None: ...

    def isForcePopups(self) -> bool: ...

    def isShowing(self) -> bool: ...

    def mouseHovered(self, __a0: docking.widgets.fieldpanel.support.FieldLocation, __a1: docking.widgets.fieldpanel.field.Field, __a2: java.awt.Rectangle, __a3: java.awt.event.MouseEvent) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeHoverService(self, hoverService: ghidra.app.decompiler.component.hover.DecompilerHoverService) -> None: ...

    def scroll(self, __a0: int) -> None: ...

    def setHoverEnabled(self, __a0: bool) -> None: ...

    def setProgram(self, __a0: ghidra.program.model.listing.Program) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

