import ghidra.program.util
import java.lang


class MarkerClickedListener(object):
    """
    Interface for notifications when the user double-clicks in the marker margin
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def markerDoubleClicked(self, location: ghidra.program.util.MarkerLocation) -> None:
        """
        Notification that the user double-clicked in the marker margin
        @param location the MarkerLocation where the user double-clicked
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

