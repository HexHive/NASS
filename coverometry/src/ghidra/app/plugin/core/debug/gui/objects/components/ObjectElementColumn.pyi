from typing import List
import docking.widgets.table
import ghidra.app.plugin.core.debug.gui.objects.components
import java.lang


class ObjectElementColumn(object, ghidra.app.plugin.core.debug.gui.objects.components.ObjectEnumeratedColumnTableModel.ObjectsEnumeratedTableColumn):




    def __init__(self, __a0: unicode, __a1: java.util.function.Function): ...



    def defaultSortDirection(self) -> docking.widgets.table.ColumnSortState.SortDirection: ...

    def equals(self, __a0: object) -> bool: ...

    @staticmethod
    def generateColumns(__a0: List[object]) -> List[ghidra.app.plugin.core.debug.gui.objects.components.ObjectEnumeratedColumnTableModel.ObjectsEnumeratedTableColumn]: ...

    def getClass(self) -> java.lang.Class: ...

    def getHeader(self) -> unicode: ...

    @overload
    def getValueOf(self, __a0: ghidra.app.plugin.core.debug.gui.objects.components.ObjectElementRow) -> object: ...

    @overload
    def getValueOf(self, __a0: object) -> object: ...

    def hashCode(self) -> int: ...

    def isEditable(self, __a0: object) -> bool: ...

    def isSortable(self) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setValueOf(self, __a0: object, __a1: object) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def header(self) -> unicode: ...

    @property
    def sortable(self) -> bool: ...