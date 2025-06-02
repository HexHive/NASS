import ghidra.app.util.html
import java.awt
import java.lang


class PlaceHolderLine(ghidra.app.util.html.ValidatableLine, object):
    """
    Marker interface for lines that are generic place holders for diffing
    """

    INVALID_COLOR: java.awt.Color = #00ffff







    def copy(self) -> ghidra.app.util.html.ValidatableLine: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getText(self) -> unicode: ...

    def hashCode(self) -> int: ...

    def isDiffColored(self) -> bool: ...

    def isValidated(self) -> bool: ...

    def matches(self, __a0: ghidra.app.util.html.ValidatableLine) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setTextColor(self, __a0: java.awt.Color) -> None: ...

    def setValidationLine(self, __a0: ghidra.app.util.html.ValidatableLine) -> None: ...

    def toString(self) -> unicode: ...

    def updateColor(self, __a0: ghidra.app.util.html.ValidatableLine, __a1: java.awt.Color) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def diffColored(self) -> bool: ...

    @property
    def text(self) -> unicode: ...

    @property
    def textColor(self) -> None: ...  # No getter available.

    @textColor.setter
    def textColor(self, value: java.awt.Color) -> None: ...

    @property
    def validated(self) -> bool: ...

    @property
    def validationLine(self) -> None: ...  # No getter available.

    @validationLine.setter
    def validationLine(self, value: ghidra.app.util.html.ValidatableLine) -> None: ...