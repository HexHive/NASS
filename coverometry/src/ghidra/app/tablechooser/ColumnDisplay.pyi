import ghidra.app.tablechooser
import ghidra.util.table.column
import java.lang
import java.util
import java.util.function


class ColumnDisplay(java.util.Comparator, object):
    """
    An interface that allows users to add columns to the TableChooserDialog.
    """









    def compare(self, __a0: object, __a1: object) -> int: ...

    @overload
    @staticmethod
    def comparing(__a0: java.util.function.Function) -> java.util.Comparator: ...

    @overload
    @staticmethod
    def comparing(__a0: java.util.function.Function, __a1: java.util.Comparator) -> java.util.Comparator: ...

    @staticmethod
    def comparingDouble(__a0: java.util.function.ToDoubleFunction) -> java.util.Comparator: ...

    @staticmethod
    def comparingInt(__a0: java.util.function.ToIntFunction) -> java.util.Comparator: ...

    @staticmethod
    def comparingLong(__a0: java.util.function.ToLongFunction) -> java.util.Comparator: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getColumnClass(self) -> java.lang.Class: ...

    def getColumnName(self) -> unicode: ...

    def getColumnValue(self, rowObject: ghidra.app.tablechooser.AddressableRowObject) -> COLUMN_TYPE: ...

    def getRenderer(self) -> ghidra.util.table.column.GColumnRenderer:
        """
        Override this method to use a custom renderer.
         <p>
         Use this method to perform any desired custom cell rendering for this column.  This method
         may be used to enable html rendering with correct table filtering.
         See {@link GColumnRenderer} and
         {@link GColumnRenderer#getFilterString(Object, ghidra.docking.settings.Settings)}.
        @return the renderer
        """
        ...

    def hashCode(self) -> int: ...

    @staticmethod
    def naturalOrder() -> java.util.Comparator: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    @staticmethod
    def nullsFirst(__a0: java.util.Comparator) -> java.util.Comparator: ...

    @staticmethod
    def nullsLast(__a0: java.util.Comparator) -> java.util.Comparator: ...

    @staticmethod
    def reverseOrder() -> java.util.Comparator: ...

    def reversed(self) -> java.util.Comparator: ...

    @overload
    def thenComparing(self, __a0: java.util.Comparator) -> java.util.Comparator: ...

    @overload
    def thenComparing(self, __a0: java.util.function.Function) -> java.util.Comparator: ...

    @overload
    def thenComparing(self, __a0: java.util.function.Function, __a1: java.util.Comparator) -> java.util.Comparator: ...

    def thenComparingDouble(self, __a0: java.util.function.ToDoubleFunction) -> java.util.Comparator: ...

    def thenComparingInt(self, __a0: java.util.function.ToIntFunction) -> java.util.Comparator: ...

    def thenComparingLong(self, __a0: java.util.function.ToLongFunction) -> java.util.Comparator: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def columnClass(self) -> java.lang.Class: ...

    @property
    def columnName(self) -> unicode: ...

    @property
    def renderer(self) -> ghidra.util.table.column.GColumnRenderer: ...