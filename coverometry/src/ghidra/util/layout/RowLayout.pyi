import java.awt
import java.lang


class RowLayout(object, java.awt.LayoutManager):
    """
    This layout arranges components in rows, putting as many components as possible on a
     row and using as many rows as necessary.
    """





    def __init__(self, hgap: int, vgap: int, preferredNumRows: int):
        """
        Constructs a new RowLayout
        @param hgap the gap (in pixels) between columns
        @param vgap the gap (in pixels) between rows
        @param preferredNumRows the prefered number of rows to use in the layout.
        """
        ...



    def addLayoutComponent(self, name: unicode, comp: java.awt.Component) -> None:
        """
        @see LayoutManager#addLayoutComponent(String, Component)
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def layoutContainer(self, parent: java.awt.Container) -> None:
        """
        @see LayoutManager#layoutContainer(Container)
        """
        ...

    def minimumLayoutSize(self, parent: java.awt.Container) -> java.awt.Dimension:
        """
        @see LayoutManager#minimumLayoutSize(Container)
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def preferredLayoutSize(self, parent: java.awt.Container) -> java.awt.Dimension:
        """
        @see LayoutManager#preferredLayoutSize(Container)
        """
        ...

    def removeLayoutComponent(self, comp: java.awt.Component) -> None:
        """
        @see LayoutManager#removeLayoutComponent(Component)
        """
        ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

