import edu.uci.ics.jung.visualization.control
import java.awt
import java.awt.event
import java.lang


class VisualGraphPopupMousePlugin(edu.uci.ics.jung.visualization.control.AbstractPopupGraphMousePlugin):




    def __init__(self): ...



    def checkModifiers(self, __a0: java.awt.event.MouseEvent) -> bool: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCursor(self) -> java.awt.Cursor: ...

    def getModifiers(self) -> int: ...

    def hashCode(self) -> int: ...

    def mouseClicked(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mouseEntered(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mouseExited(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mousePressed(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mouseReleased(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setCursor(self, __a0: java.awt.Cursor) -> None: ...

    def setModifiers(self, __a0: int) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

