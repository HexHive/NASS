import java.awt.event
import java.lang
import javax.swing


class Playable(object):








    def clicked(self, e: java.awt.event.MouseEvent) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getImageIcon(self) -> javax.swing.Icon: ...

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

    @property
    def imageIcon(self) -> javax.swing.Icon: ...