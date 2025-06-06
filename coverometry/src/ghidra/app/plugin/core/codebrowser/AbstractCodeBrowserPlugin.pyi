from typing import List
import docking.action
import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.support
import ghidra.app.nav
import ghidra.app.plugin.core.codebrowser
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


class AbstractCodeBrowserPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.CodeViewerService, ghidra.app.services.CodeFormatService, ghidra.framework.options.OptionsChangeListener, ghidra.app.util.viewer.format.FormatModelListener, ghidra.framework.model.DomainObjectListener, ghidra.app.plugin.core.codebrowser.CodeBrowserPluginInterface):




    def __init__(self, __a0: ghidra.framework.plugintool.PluginTool): ...



    def accept(self, __a0: java.net.URL) -> bool: ...

    def acceptData(self, __a0: List[ghidra.framework.model.DomainFile]) -> bool: ...

    def addButtonPressedListener(self, __a0: ghidra.app.services.ButtonPressedListener) -> None: ...

    def addListingDisplayListener(self, __a0: ghidra.app.util.viewer.listingpanel.AddressSetDisplayListener) -> None: ...

    def addLocalAction(self, __a0: docking.action.DockingAction) -> None: ...

    def addMarginProvider(self, __a0: ghidra.app.util.viewer.listingpanel.MarginProvider) -> None: ...

    def addOverviewProvider(self, __a0: ghidra.app.util.viewer.listingpanel.OverviewProvider) -> None: ...

    def addProgramDropProvider(self, __a0: ghidra.app.util.ProgramDropProvider) -> None: ...

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

    def getTransientState(self) -> object: ...

    def getUndoRedoState(self, __a0: ghidra.framework.model.DomainObject) -> object: ...

    def getView(self) -> ghidra.program.model.address.AddressSetView: ...

    def getViewManager(self, __a0: ghidra.app.plugin.core.codebrowser.CodeViewerProvider) -> ghidra.app.services.ViewManagerService: ...

    @overload
    def goTo(self, __a0: ghidra.program.util.ProgramLocation) -> bool: ...

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

    def restoreTransientState(self, __a0: object) -> None: ...

    def restoreUndoRedoState(self, __a0: ghidra.framework.model.DomainObject, __a1: object) -> None: ...

    def selectionChanged(self, __a0: ghidra.app.plugin.core.codebrowser.CodeViewerProvider, __a1: ghidra.program.util.ProgramSelection) -> None: ...

    def serviceAdded(self, __a0: java.lang.Class, __a1: object) -> None: ...

    def serviceRemoved(self, __a0: java.lang.Class, __a1: object) -> None: ...

    def setCoordinatedListingPanelListener(self, __a0: ghidra.app.services.CoordinatedListingPanelListener) -> None: ...

    def setHighlightProvider(self, __a0: ghidra.app.util.ListingHighlightProvider, __a1: ghidra.program.model.listing.Program) -> None: ...

    def setListingPanel(self, __a0: ghidra.app.util.viewer.listingpanel.ListingPanel) -> None: ...

    def setNorthComponent(self, __a0: javax.swing.JComponent) -> None: ...

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
    def addressIndexMap(self) -> ghidra.app.util.viewer.util.AddressIndexMap: ...

    @property
    def coordinatedListingPanelListener(self) -> None: ...  # No getter available.

    @coordinatedListingPanelListener.setter
    def coordinatedListingPanelListener(self, value: ghidra.app.services.CoordinatedListingPanelListener) -> None: ...

    @property
    def currentAddress(self) -> ghidra.program.model.address.Address: ...

    @property
    def currentField(self) -> ghidra.app.util.viewer.field.ListingField: ...

    @property
    def currentFieldLoction(self) -> docking.widgets.fieldpanel.support.FieldLocation: ...

    @property
    def currentFieldText(self) -> unicode: ...

    @property
    def currentFieldTextSelection(self) -> unicode: ...

    @property
    def currentLocation(self) -> ghidra.program.util.ProgramLocation: ...

    @property
    def currentSelection(self) -> ghidra.program.util.ProgramSelection: ...

    @property
    def fieldPanel(self) -> docking.widgets.fieldpanel.FieldPanel: ...

    @property
    def formatManager(self) -> ghidra.app.util.viewer.format.FormatManager: ...

    @property
    def listingModel(self) -> ghidra.app.util.viewer.listingpanel.ListingModel: ...

    @property
    def listingPanel(self) -> ghidra.app.util.viewer.listingpanel.ListingPanel: ...

    @listingPanel.setter
    def listingPanel(self, value: ghidra.app.util.viewer.listingpanel.ListingPanel) -> None: ...

    @property
    def navigatable(self) -> ghidra.app.nav.Navigatable: ...

    @property
    def northComponent(self) -> None: ...  # No getter available.

    @northComponent.setter
    def northComponent(self, value: javax.swing.JComponent) -> None: ...

    @property
    def provider(self) -> ghidra.app.plugin.core.codebrowser.CodeViewerProvider: ...

    @property
    def view(self) -> ghidra.program.model.address.AddressSetView: ...