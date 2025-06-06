from typing import List
import docking.widgets.table
import ghidra.app.plugin.core.debug.gui.model
import ghidra.docking.settings
import ghidra.framework.plugintool
import ghidra.trace.model
import ghidra.util.table.column
import java.lang
import java.util


class TraceValueLifePlotColumn(docking.widgets.table.AbstractDynamicTableColumn):




    def __init__(self): ...



    def addSeekListener(self, __a0: docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getColumnClass(self) -> java.lang.Class: ...

    def getColumnDescription(self) -> unicode: ...

    def getColumnDisplayName(self, __a0: ghidra.docking.settings.Settings) -> unicode: ...

    def getColumnName(self) -> unicode: ...

    def getColumnPreferredWidth(self) -> int: ...

    def getColumnRenderer(self) -> ghidra.util.table.column.GColumnRenderer: ...

    @overload
    def getComparator(self) -> java.util.Comparator: ...

    @overload
    def getComparator(self, __a0: docking.widgets.table.DynamicColumnTableModel, __a1: int) -> java.util.Comparator: ...

    def getHeaderRenderer(self) -> docking.widgets.table.GTableHeaderRenderer: ...

    def getMaxLines(self, __a0: ghidra.docking.settings.Settings) -> int: ...

    def getSettingsDefinitions(self) -> List[ghidra.docking.settings.SettingsDefinition]: ...

    def getSupportedRowType(self) -> java.lang.Class: ...

    def getUniqueIdentifier(self) -> unicode: ...

    @overload
    def getValue(self, __a0: ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow, __a1: ghidra.docking.settings.Settings, __a2: ghidra.trace.model.Trace, __a3: ghidra.framework.plugintool.ServiceProvider) -> ghidra.trace.model.Lifespan.LifeSet: ...

    @overload
    def getValue(self, __a0: object, __a1: ghidra.docking.settings.Settings, __a2: object, __a3: ghidra.framework.plugintool.ServiceProvider) -> object: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setFullRange(self, __a0: ghidra.trace.model.Lifespan) -> None: ...

    def setSnap(self, __a0: long) -> None: ...

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

    @property
    def fullRange(self) -> None: ...  # No getter available.

    @fullRange.setter
    def fullRange(self, value: ghidra.trace.model.Lifespan) -> None: ...

    @property
    def headerRenderer(self) -> docking.widgets.table.GTableHeaderRenderer: ...

    @property
    def snap(self) -> None: ...  # No getter available.

    @snap.setter
    def snap(self, value: long) -> None: ...