import docking
import ghidra.app.context
import ghidra.app.nav
import ghidra.app.util.viewer.util
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.awt
import java.awt.event
import java.lang


class DualListingActionContext(ghidra.app.context.NavigatableActionContext, ghidra.app.util.viewer.util.CodeComparisonPanelActionContext):
    """
    Action context for a ListingCodeComparisonPanel.
    """





    @overload
    def __init__(self, provider: docking.ComponentProvider, navigatable: ghidra.app.nav.Navigatable):
        """
        Constructor for a dual listing's action context.
        @param provider the provider that uses this action context.
        @param navigatable the navigatable for this action context.
        """
        ...

    @overload
    def __init__(self, provider: docking.ComponentProvider, navigatable: ghidra.app.nav.Navigatable, location: ghidra.program.util.ProgramLocation):
        """
        Constructor for a dual listing's action context.
        @param provider the provider that uses this action context.
        @param navigatable the navigatable for this action context.
        @param location the location indicated by this context.
        """
        ...

    @overload
    def __init__(self, provider: docking.ComponentProvider, navigatable: ghidra.app.nav.Navigatable, program: ghidra.program.model.listing.Program, location: ghidra.program.util.ProgramLocation, selection: ghidra.program.util.ProgramSelection, highlight: ghidra.program.util.ProgramSelection):
        """
        Constructor for a dual listing's action context.
        @param provider the provider that uses this action context.
        @param navigatable the navigatable for this action context.
        @param program the program in the listing providing this context.
        @param location the location indicated by this context.
        @param selection the listing selection for this context.
        @param highlight the listing highlight for this context.
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        @return address corresponding to the action's program location or null
         if program location is null.
        """
        ...

    def getClass(self) -> java.lang.Class: ...

    def getCodeComparisonPanel(self) -> ghidra.app.util.viewer.util.CodeComparisonPanel: ...

    def getCodeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        """
        Returns the code unit containing the action's program location or null
        @return the code unit containing the action's program location or null
        """
        ...

    def getComponentProvider(self) -> docking.ComponentProvider: ...

    def getContextObject(self) -> object: ...

    def getEventClickModifiers(self) -> int: ...

    def getHighlight(self) -> ghidra.program.util.ProgramSelection: ...

    def getLocation(self) -> ghidra.program.util.ProgramLocation:
        """
        @return Returns the program location.
        """
        ...

    def getMouseEvent(self) -> java.awt.event.MouseEvent: ...

    def getNavigatable(self) -> ghidra.app.nav.Navigatable: ...

    def getProgram(self) -> ghidra.program.model.listing.Program: ...

    def getSelection(self) -> ghidra.program.util.ProgramSelection:
        """
        @return Returns the program selection.
        """
        ...

    def getSourceComponent(self) -> java.awt.Component: ...

    def getSourceObject(self) -> object: ...

    def hasAnyEventClickModifiers(self, modifiersMask: int) -> bool: ...

    def hasHighlight(self) -> bool: ...

    def hasSelection(self) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setCodeComparisonPanel(self, codeComparisonPanel: ghidra.app.util.viewer.util.CodeComparisonPanel) -> None:
        """
        Sets the CodeComparisonPanel associated with this context.
        @param codeComparisonPanel the code comparison panel
        """
        ...

    def setContextObject(self, contextObject: object) -> docking.DefaultActionContext: ...

    def setEventClickModifiers(self, modifiers: int) -> None: ...

    def setMouseEvent(self, e: java.awt.event.MouseEvent) -> docking.DefaultActionContext: ...

    def setSourceObject(self, sourceObject: object) -> docking.DefaultActionContext: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def codeComparisonPanel(self) -> ghidra.app.util.viewer.util.CodeComparisonPanel: ...

    @codeComparisonPanel.setter
    def codeComparisonPanel(self, value: ghidra.app.util.viewer.util.CodeComparisonPanel) -> None: ...