import ghidra.app.util.html
import ghidra.program.model.data
import java.awt
import java.lang


class EmptyDataTypeLine(ghidra.app.util.html.DataTypeLine, ghidra.app.util.html.PlaceHolderLine):




    def __init__(self): ...



    def copy(self) -> ghidra.app.util.html.ValidatableLine: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getComment(self) -> unicode: ...

    def getCommentColor(self) -> java.awt.Color: ...

    def getDataType(self) -> ghidra.program.model.data.DataType: ...

    def getName(self) -> unicode: ...

    def getNameColor(self) -> java.awt.Color: ...

    def getText(self) -> unicode: ...

    def getType(self) -> unicode: ...

    def getTypeColor(self) -> java.awt.Color: ...

    def hasUniversalId(self) -> bool: ...

    def hashCode(self) -> int: ...

    def isDiffColored(self) -> bool: ...

    def isValidated(self) -> bool: ...

    def matches(self, otherValidatableLine: ghidra.app.util.html.ValidatableLine) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def setCommentColor(self, commentColor: java.awt.Color) -> None: ...

    def setNameColor(self, nameColor: java.awt.Color) -> None: ...

    def setTextColor(self, color: java.awt.Color) -> None: ...

    def setTypeColor(self, typeColor: java.awt.Color) -> None: ...

    def setValidationLine(self, line: ghidra.app.util.html.ValidatableLine) -> None: ...

    def toString(self) -> unicode: ...

    def updateColor(self, otherValidatableLine: ghidra.app.util.html.ValidatableLine, invalidColor: java.awt.Color) -> None: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def validated(self) -> bool: ...