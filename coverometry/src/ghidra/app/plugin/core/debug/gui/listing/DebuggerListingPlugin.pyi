from typing import List
import docking.action
import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.support
import ghidra.app.nav
import ghidra.app.plugin.core.codebrowser
import ghidra.app.plugin.core.debug.gui.action
import ghidra.app.plugin.core.debug.gui.listing
import ghidra.app.services
import ghidra.app.util
import ghidra.app.util.viewer.format
import ghidra.app.util.viewer.listingpanel
import ghidra.app.util.viewer.util
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.framework.plugintool.util
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import java.lang
import java.net
import javax.swing


class DebuggerListingPlugin(ghidra.app.plugin.core.codebrowser.AbstractCodeBrowserPlugin, ghidra.app.services.DebuggerListingService):




    def __init__(self, __a0: ghidra.framework.plugintool.PluginTool): ...



    def accept(self, __a0: java.net.URL) -> bool: ...

    def acceptData(self, __a0: List[ghidra.framework.model.DomainFile]) -> bool: ...

    def addButtonPressedListener(self, __a0: ghidra.app.services.ButtonPressedListener) -> None: ...

    def addListingDisplayListener(self, __a0: ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener) -> None: ...

    def addLocalAction(self, __a0: docking.action.DockingAction) -> None: ...

    def addMarginProvider(self, __a0: ghidra.app.util.viewer.listingpanel.MarginProvider) -> None: ...

    def addOverviewProvider(self, __a0: ghidra.app.util.viewer.listingpanel.OverviewProvider) -> None: ...

    def addProgramDropProvider(self, __a0: ghidra.app.util.ProgramDropProvider) -> None: ...

    def addTrackingSpecChangeListener(self, __a0: ghidra.app.services.DebuggerListingService.LocationTrackingSpecChangeListener) -> None: ...

    def createListingBackgroundColorModel(self, __a0: ghidra.app.util.viewer.listingpanel.ListingPanel) -> ghidra.app.plugin.core.debug.gui.listing.MultiBlendedListingBackgroundColorModel: ...

    def createListingIfMissing(self, __a0: ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec, __a1: bool) -> ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider: ...

    def createNewDisconnectedProvider(self) -> ghidra.app.plugin.core.codebrowser.CodeViewerProvider: ...

    def dataStateRestoreCompleted(self) -> None: ...

    def dependsUpon(self, __a0: ghidra.framework.plugintool.Plugin) -> bool: ...

    def domainObjectChanged(self, __a0: ghidra.framework.model.DomainObjectChangedEvent) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def eventSent(self, __a0: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def firePluginEvent(self, __a0: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def formatModelAdded(self, __a0: ghidra.app.util.viewer.format.FieldFormatModel) -> None: ...

    def formatModelChanged(self, __a0: ghidra.app.util.viewer.format.FieldFormatModel) -> None: ...

    def formatModelRemoved(self, __a0: ghidra.app.util.viewer.format.FieldFormatModel) -> None: ...

    def getAddressIndexMap(self) -> ghidra.app.util.viewer.util.AddressIndexMap: ...

    def getClass(self) -> java.lang.Class: ...

    def getCurrentAddress(self) -> ghidra.program.model.address.Address: ...

    def getCurrentField(self) -> docking.widgets.fieldpanel.field.Field: ...

    def getCurrentFieldLoction(self) -> docking.widgets.fieldpanel.support.FieldLocation: ...

    def getCurrentFieldText(self) -> unicode: ...

    def getCurrentFieldTextSelection(self) -> unicode: ...

    def getCurrentLocation(self) -> ghidra.program.util.ProgramLocation: ...

    def getCurrentSelection(self) -> ghidra.program.util.ProgramSelection: ...

    def getData(self) -> List[ghidra.framework.model.DomainFile]: ...

    def getFieldPanel(self) -> docking.widgets.fieldpanel.FieldPanel: ...

    def getFormatManager(self) -> ghidra.app.util.viewer.format.FormatManager: ...

    def getListingModel(self) -> ghidra.app.util.viewer.listingpanel.ListingModel: ...

    def getListingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel: ...

    def getMissingRequiredServices(self) -> List[object]: ...

    def getName(self) -> unicode: ...

    def getNavigatable(self) -> ghidra.app.nav.Navigatable: ...

    def getPluginDescription(self) -> ghidra.framework.plugintool.util.PluginDescription: ...

    def getProvider(self) -> ghidra.app.plugin.core.codebrowser.CodeViewerProvider: ...

    def getSupportedDataTypes(self) -> List[java.lang.Class]: ...

    def getTool(self) -> ghidra.framework.plugintool.PluginTool: ...

    def getTrackingSpec(self) -> ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec: ...

    def getTransientState(self) -> object: ...

    def getUndoRedoState(self, __a0: ghidra.framework.model.DomainObject) -> object: ...

    def getView(self) -> ghidra.program.model.address.AddressSetView: ...

    def getViewManager(self, __a0: ghidra.app.plugin.core.codebrowser.CodeViewerProvider) -> ghidra.app.services.ViewManagerService: ...

    @overload
    def goTo(self, __a0: ghidra.program.util.ProgramLocation) -> bool: ...

    @overload
    def goTo(self, __a0: ghidra.program.model.address.Address, __a1: bool) -> bool: ...

    @overload
    def goTo(self, __a0: ghidra.program.util.ProgramLocation, __a1: bool) -> bool: ...

    @overload
    def goToField(self, __a0: ghidra.program.model.address.Address, __a1: unicode, __a2: int, __a3: int) -> bool: ...

    @overload
    def goToField(self, __a0: ghidra.program.model.address.Address, __a1: unicode, __a2: int, __a3: int, __a4: int) -> bool: ...

    @overload
    def goToField(self, __a0: ghidra.program.model.address.Address, __a1: unicode, __a2: int, __a3: int, __a4: int, __a5: bool) -> bool: ...

    def hasMissingRequiredService(self) -> bool: ...

    def hashCode(self) -> int: ...

    def highlightChanged(self, __a0: ghidra.app.plugin.core.codebrowser.CodeViewerProvider, __a1: ghidra.program.util.ProgramSelection) -> None: ...

    def isDisposed(self) -> bool: ...

    def locationChanged(self, __a0: ghidra.app.plugin.core.codebrowser.CodeViewerProvider, __a1: ghidra.program.util.ProgramLocation) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def optionsChanged(self, __a0: ghidra.framework.options.ToolOptions, __a1: unicode, __a2: object, __a3: object) -> None: ...

    def processEvent(self, __a0: ghidra.framework.plugintool.PluginEvent) -> None: ...

    def providerClosed(self, __a0: ghidra.app.plugin.core.codebrowser.CodeViewerProvider) -> None: ...

    def readConfigState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    def readDataState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    def removeButtonPressedListener(self, __a0: ghidra.app.services.ButtonPressedListener) -> None: ...

    def removeHighlightProvider(self, __a0: ghidra.app.util.ListingHighlightProvider, __a1: ghidra.program.model.listing.Program) -> None: ...

    def removeListingDisplayListener(self, __a0: ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener) -> None: ...

    def removeListingPanel(self, __a0: ghidra.app.util.viewer.listingpanel.ListingPanel) -> None: ...

    def removeLocalAction(self, __a0: docking.action.DockingAction) -> None: ...

    def removeMarginProvider(self, __a0: ghidra.app.util.viewer.listingpanel.MarginProvider) -> None: ...

    def removeOverviewProvider(self, __a0: ghidra.app.util.viewer.listingpanel.OverviewProvider) -> None: ...

    def removeTrackingSpecChangeListener(self, __a0: ghidra.app.services.DebuggerListingService.LocationTrackingSpecChangeListener) -> None: ...

    def restoreTransientState(self, __a0: object) -> None: ...

    def restoreUndoRedoState(self, __a0: ghidra.framework.model.DomainObject, __a1: object) -> None: ...

    def selectionChanged(self, __a0: ghidra.app.plugin.core.codebrowser.CodeViewerProvider, __a1: ghidra.program.util.ProgramSelection) -> None: ...

    def serviceAdded(self, __a0: java.lang.Class, __a1: object) -> None: ...

    def serviceRemoved(self, __a0: java.lang.Class, __a1: object) -> None: ...

    def setCoordinatedListingPanelListener(self, __a0: ghidra.app.services.CoordinatedListingPanelListener) -> None: ...

    def setCurrentSelection(self, __a0: ghidra.program.util.ProgramSelection) -> None: ...

    def setHighlightProvider(self, __a0: ghidra.app.util.ListingHighlightProvider, __a1: ghidra.program.model.listing.Program) -> None: ...

    def setListingPanel(self, __a0: ghidra.app.util.viewer.listingpanel.ListingPanel) -> None: ...

    def setNorthComponent(self, __a0: javax.swing.JComponent) -> None: ...

    def setTraceManager(self, __a0: ghidra.app.services.DebuggerTraceManagerService) -> None: ...

    def setTrackingSpec(self, __a0: ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec) -> None: ...

    def toString(self) -> unicode: ...

    def toggleOpen(self, __a0: ghidra.program.model.listing.Data) -> None: ...

    def updateDisplay(self) -> None: ...

    def updateNow(self) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    def writeConfigState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    def writeDataState(self, __a0: ghidra.framework.options.SaveState) -> None: ...

    @property
    def currentSelection(self) -> ghidra.program.util.ProgramSelection: ...

    @currentSelection.setter
    def currentSelection(self, value: ghidra.program.util.ProgramSelection) -> None: ...

    @property
    def traceManager(self) -> None: ...  # No getter available.

    @traceManager.setter
    def traceManager(self, value: ghidra.app.services.DebuggerTraceManagerService) -> None: ...

    @property
    def trackingSpec(self) -> ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec: ...

    @trackingSpec.setter
    def trackingSpec(self, value: ghidra.app.plugin.core.debug.gui.action.LocationTrackingSpec) -> None: ...

    @property
    def transientState(self) -> object: ...