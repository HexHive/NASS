import java.awt.event
import java.lang
import org.jungrapht.visualization.control


class JgtGraphMouse(org.jungrapht.visualization.control.DefaultGraphMouse):




    def __init__(self, __a0: ghidra.graph.visualization.DefaultGraphDisplay, __a1: bool): ...



    def add(self, __a0: org.jungrapht.visualization.control.GraphMousePlugin) -> None: ...

    def allowsEdgeSelection(self) -> bool: ...

    @staticmethod
    def builder() -> org.jungrapht.visualization.control.DefaultGraphMouse.Builder: ...

    def clear(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def isPluginsLoaded(self) -> bool: ...

    def loadPlugins(self) -> None: ...

    def mouseClicked(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mouseDragged(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mouseEntered(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mouseExited(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mouseMoved(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mousePressed(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mouseReleased(self, __a0: java.awt.event.MouseEvent) -> None: ...

    def mouseWheelMoved(self, __a0: java.awt.event.MouseWheelEvent) -> None: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def remove(self, __a0: org.jungrapht.visualization.control.GraphMousePlugin) -> None: ...

    def setPluginsLoaded(self) -> None: ...

    def setZoomAtMouse(self, __a0: bool) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

