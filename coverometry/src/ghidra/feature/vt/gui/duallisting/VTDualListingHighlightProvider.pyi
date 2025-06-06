from typing import List
import docking.widgets.fieldpanel.support
import ghidra.app.util
import ghidra.app.util.viewer.field
import ghidra.app.util.viewer.listingpanel
import ghidra.feature.vt.api.main
import java.lang


class VTDualListingHighlightProvider(object, ghidra.app.util.ListingHighlightProvider):
    NO_HIGHLIGHTS: List[docking.widgets.fieldpanel.support.Highlight] = array(docking.widgets.fieldpanel.support.Highlight)



    def __init__(self, __a0: ghidra.feature.vt.gui.plugin.VTController, __a1: bool): ...



    def createHighlights(self, __a0: unicode, __a1: ghidra.app.util.viewer.field.ListingField, __a2: int) -> List[docking.widgets.fieldpanel.support.Highlight]: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getMarkupItem(self) -> ghidra.feature.vt.api.main.VTMarkupItem: ...

    def hashCode(self) -> int: ...

    def isSource(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setListingPanel(self, __a0: ghidra.app.util.viewer.listingpanel.ListingPanel) -> None: ...

    def setMarkupItem(self, __a0: ghidra.feature.vt.api.main.VTMarkupItem) -> None: ...

    def toString(self) -> unicode: ...

    def updateMarkup(self) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def listingPanel(self) -> None: ...  # No getter available.

    @listingPanel.setter
    def listingPanel(self, value: ghidra.app.util.viewer.listingpanel.ListingPanel) -> None: ...

    @property
    def markupItem(self) -> ghidra.feature.vt.api.main.VTMarkupItem: ...

    @markupItem.setter
    def markupItem(self, value: ghidra.feature.vt.api.main.VTMarkupItem) -> None: ...

    @property
    def source(self) -> bool: ...