import java.awt
import java.io
import java.lang


class RightSidedSquishyBuddyLayout(object, java.awt.LayoutManager, java.io.Serializable):
    """
    Layout for two components laid out horizontally where the first component gets its preferred width
     and the second component gets the remaining space up to its preferred width.
    """





    @overload
    def __init__(self, hGap: int): ...

    @overload
    def __init__(self, hGap: int, rightAlign: bool): ...



    def addLayoutComponent(self, name: unicode, comp: java.awt.Component) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def layoutContainer(self, container: java.awt.Container) -> None: ...

    def minimumLayoutSize(self, cont: java.awt.Container) -> java.awt.Dimension: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def preferredLayoutSize(self, container: java.awt.Container) -> java.awt.Dimension: ...

    def removeLayoutComponent(self, comp: java.awt.Component) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

