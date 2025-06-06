import ghidra.app.util.html
import java.awt
import java.lang


class TextLine(object, ghidra.app.util.html.ValidatableLine):
    INVALID_COLOR: java.awt.Color = #00ffff



    def __init__(self, text: unicode): ...



    def copy(self) -> ghidra.app.util.html.ValidatableLine: ...

    def equals(self, obj: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getText(self) -> unicode: ...

    def getTextColor(self) -> java.awt.Color: ...

    def hashCode(self) -> int: ...

    def isDiffColored(self) -> bool: ...

    def isValidated(self) -> bool: ...

    def matches(self, otherLine: ghidra.app.util.html.ValidatableLine) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setTextColor(self, color: java.awt.Color) -> None: ...

    def setValidationLine(self, line: ghidra.app.util.html.ValidatableLine) -> None: ...

    def toString(self) -> unicode: ...

    def updateColor(self, otherLine: ghidra.app.util.html.ValidatableLine, invalidColor: java.awt.Color) -> None: ...

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
    def textColor(self) -> java.awt.Color: ...

    @textColor.setter
    def textColor(self, value: java.awt.Color) -> None: ...

    @property
    def validated(self) -> bool: ...

    @property
    def validationLine(self) -> None: ...  # No getter available.

    @validationLine.setter
    def validationLine(self, value: ghidra.app.util.html.ValidatableLine) -> None: ...