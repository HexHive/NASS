from typing import Iterator
import docking.widgets.fieldpanel
import docking.widgets.fieldpanel.listener
import java.awt
import java.lang
import java.util
import java.util.function


class ByteViewerLayoutModel(object, docking.widgets.fieldpanel.LayoutModel):




    def __init__(self): ...

    def __iter__(self): ...

    def addLayoutModelListener(self, __a0: docking.widgets.fieldpanel.listener.LayoutModelListener) -> None: ...

    def dataChanged(self, __a0: long, __a1: long) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def flushChanges(self) -> None: ...

    def forEach(self, __a0: java.util.function.Consumer) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    @overload
    def getIndexAfter(self, __a0: int) -> int: ...

    @overload
    def getIndexAfter(self, __a0: long) -> long: ...

    def getIndexBefore(self, __a0: long) -> long: ...

    def getLayout(self, __a0: long) -> docking.widgets.fieldpanel.Layout: ...

    def getNumIndexes(self) -> long: ...

    def getPreferredViewSize(self) -> java.awt.Dimension: ...

    def hashCode(self) -> int: ...

    def indexSetChanged(self) -> None: ...

    def isUniform(self) -> bool: ...

    @overload
    def iterator(self) -> java.util.Iterator: ...

    @overload
    def iterator(self, __a0: long) -> docking.widgets.fieldpanel.LayoutModelIterator: ...

    def layoutChanged(self) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeLayoutModelListener(self, __a0: docking.widgets.fieldpanel.listener.LayoutModelListener) -> None: ...

    def spliterator(self) -> java.util.Spliterator: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def numIndexes(self) -> long: ...

    @property
    def preferredViewSize(self) -> java.awt.Dimension: ...

    @property
    def uniform(self) -> bool: ...