from typing import List
import docking.widgets.table
import ghidra.docking.settings
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.table.field
import java.lang
import java.util


class PreviewTableColumn(ghidra.util.table.field.ProgramLocationTableColumnExtensionPoint):
    """
    This table column displays a preview of the ProgramLocation with a row in the table.
     The actual content displayed will vary, depending upon the location.  Further, the preview is
     meant to mimic what the user will see displayed in the Listing display window.
    """





    def __init__(self): ...



    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getColumnClass(self) -> java.lang.Class: ...

    def getColumnDescription(self) -> unicode: ...

    def getColumnDisplayName(self, settings: ghidra.docking.settings.Settings) -> unicode: ...

    def getColumnName(self) -> unicode: ...

    def getColumnPreferredWidth(self) -> int: ...

    def getColumnRenderer(self) -> ghidra.util.table.column.GColumnRenderer: ...

    @overload
    def getComparator(self) -> java.util.Comparator: ...

    @overload
    def getComparator(self, model: docking.widgets.table.DynamicColumnTableModel, columnIndex: int) -> java.util.Comparator: ...

    def getHeaderRenderer(self) -> docking.widgets.table.GTableHeaderRenderer: ...

    def getMaxLines(self, settings: ghidra.docking.settings.Settings) -> int: ...

    @overload
    def getProgramLocation(self, rowObject: ghidra.program.util.ProgramLocation, settings: ghidra.docking.settings.Settings, program: ghidra.program.model.listing.Program, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.util.ProgramLocation: ...

    @overload
    def getProgramLocation(self, __a0: object, __a1: ghidra.docking.settings.Settings, __a2: ghidra.program.model.listing.Program, __a3: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.util.ProgramLocation: ...

    def getSettingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getSupportedRowType(self) -> java.lang.Class: ...

    def getUniqueIdentifier(self) -> unicode: ...

    @overload
    def getValue(self, rowObject: ghidra.program.util.ProgramLocation, settings: ghidra.docking.settings.Settings, program: ghidra.program.model.listing.Program, serviceProvider: ghidra.framework.plugintool.ServiceProvider) -> ghidra.util.table.PreviewTableCellData: ...

    @overload
    def getValue(self, __a0: object, __a1: ghidra.docking.settings.Settings, __a2: object, __a3: ghidra.framework.plugintool.ServiceProvider) -> object: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def columnName(self) -> unicode: ...

    @property
    def columnRenderer(self) -> ghidra.util.table.column.GColumnRenderer: ...