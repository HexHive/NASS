import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.internal
import docking.widgets.fieldpanel.support
import ghidra.app.decompiler
import java.awt
import java.lang
import javax.swing


class ClangTextField(docking.widgets.fieldpanel.field.WrappingVerticalLayoutTextField):




    def __init__(self, __a0: List[object], __a1: List[docking.widgets.fieldpanel.field.FieldElement], __a2: int, __a3: int, __a4: int, __a5: docking.widgets.fieldpanel.support.FieldHighlightFactory): ...



    def contains(self, x: int, y: int) -> bool: ...

    def dataToScreenLocation(self, dataRow: int, dataColumn: int) -> docking.widgets.fieldpanel.support.RowColLocation: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getCol(self, row: int, x: int) -> int: ...

    def getCursorBounds(self, row: int, col: int) -> java.awt.Rectangle: ...

    def getFieldElement(self, screenRow: int, screenColumn: int) -> docking.widgets.fieldpanel.field.FieldElement: ...

    def getHeight(self) -> int: ...

    def getHeightAbove(self) -> int: ...

    def getHeightBelow(self) -> int: ...

    def getLineNumber(self) -> int: ...

    def getNumCols(self, row: int) -> int: ...

    def getNumDataRows(self) -> int: ...

    def getNumRows(self) -> int: ...

    def getPreferredWidth(self) -> int: ...

    def getRow(self, y: int) -> int: ...

    def getScrollableUnitIncrement(self, topOfScreen: int, direction: int, max: int) -> int: ...

    def getStartX(self) -> int: ...

    def getText(self) -> unicode: ...

    def getTextWithLineSeparators(self) -> unicode: ...

    def getToken(self, loc: docking.widgets.fieldpanel.support.FieldLocation) -> ghidra.app.decompiler.ClangToken:
        """
        Gets the C language token at the indicated location.
        @param loc the field location
        @return the token
        """
        ...

    def getWidth(self) -> int: ...

    def getX(self, row: int, col: int) -> int: ...

    def getY(self, row: int) -> int: ...

    def hashCode(self) -> int: ...

    def isClipped(self) -> bool: ...

    def isPrimary(self) -> bool: ...

    def isValid(self, row: int, col: int) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def paint(self, c: javax.swing.JComponent, g: java.awt.Graphics, context: docking.widgets.fieldpanel.internal.PaintContext, clip: java.awt.Rectangle, colorManager: docking.widgets.fieldpanel.internal.FieldBackgroundColorManager, cursorLoc: docking.widgets.fieldpanel.support.RowColLocation, rowHeight: int) -> None: ...

    def rowHeightChanged(self, heightAbove1: int, heightBelow: int) -> None: ...

    def screenLocationToTextOffset(self, row: int, col: int) -> int: ...

    def screenToDataLocation(self, screenRow: int, screenColumn: int) -> docking.widgets.fieldpanel.support.RowColLocation: ...

    def setPrimary(self, state: bool) -> None:
        """
        Sets the primary State.
        @param state the state to set.
        """
        ...

    def textOffsetToScreenLocation(self, textOffset: int) -> docking.widgets.fieldpanel.support.RowColLocation: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def lineNumber(self) -> int: ...