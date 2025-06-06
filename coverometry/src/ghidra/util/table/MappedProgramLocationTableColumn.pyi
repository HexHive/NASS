from typing import List
import docking.widgets.table
import ghidra.docking.settings
import ghidra.framework.plugintool
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.table.column
import ghidra.util.table.field
import java.lang
import java.util


class MappedProgramLocationTableColumn(docking.widgets.table.MappedTableColumn, ghidra.util.table.field.ProgramLocationTableColumn):








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

    def getMappedColumnClass(self) -> java.lang.Class:
        """
        Returns the class of the column that this mapper wraps
        @return the class of the column that this mapper wraps
        """
        ...

    def getMaxLines(self, settings: ghidra.docking.settings.Settings) -> int: ...

    def getProgramLocation(self, __a0: object, __a1: ghidra.docking.settings.Settings, __a2: ghidra.program.model.listing.Program, __a3: ghidra.framework.plugintool.ServiceProvider) -> ghidra.program.util.ProgramLocation: ...

    def getSettingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getSupportedRowType(self) -> java.lang.Class: ...

    def getUniqueIdentifier(self) -> unicode: ...

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

