import java.awt
import java.lang


class ScrollpaneAlignedHorizontalLayout(object, java.awt.LayoutManager):




    def __init__(self, scroller: docking.widgets.indexedscrollpane.IndexedScrollPane): ...



    def addLayoutComponent(self, name: unicode, comp: java.awt.Component) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def layoutContainer(self, parent: java.awt.Container) -> None: ...

    def minimumLayoutSize(self, parent: java.awt.Container) -> java.awt.Dimension: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def preferredLayoutSize(self, parent: java.awt.Container) -> java.awt.Dimension: ...

    def removeLayoutComponent(self, comp: java.awt.Component) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

