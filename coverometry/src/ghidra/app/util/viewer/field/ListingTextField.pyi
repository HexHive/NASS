from typing import List
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.internal
import docking.widgets.fieldpanel.support
import ghidra.app.util
import ghidra.app.util.viewer.field
import ghidra.app.util.viewer.proxy
import java.awt
import java.lang
import javax.swing


class ListingTextField(object, ghidra.app.util.viewer.field.ListingField, docking.widgets.fieldpanel.field.TextField):
    """
    ListingField implementation for text fields.
    """









    def contains(self, x: int, y: int) -> bool: ...

    @staticmethod
    def createMultilineTextField(factory: ghidra.app.util.viewer.field.FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj, textElements: List[docking.widgets.fieldpanel.field.FieldElement], startX: int, width: int, maxLines: int, provider: ghidra.app.util.ListingHighlightProvider) -> ghidra.app.util.viewer.field.ListingTextField:
        """
        Displays the given array of text, each on its own line.
        @param factory the field factory that generated this field
        @param proxy the object used to populate this field
        @param textElements the array of elements for the field.
         Each of these holds text, attributes and location information.
        @param startX the starting X position of the field
        @param width the width of the field
        @param maxLines the maxLines to display.
        @param provider the highlight provider
        @return the text field.
        """
        ...

    @staticmethod
    def createPackedTextField(factory: ghidra.app.util.viewer.field.FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj, textElements: List[docking.widgets.fieldpanel.field.FieldElement], startX: int, width: int, maxLines: int, provider: ghidra.app.util.ListingHighlightProvider) -> ghidra.app.util.viewer.field.ListingTextField:
        """
        Displays the list of text strings, packing as many as it can on a line before wrapping to
         the next line.
        @param factory the field factory that generated this field
        @param proxy the object used to populate this field
        @param textElements the array of elements for the field.
         Each of these holds text, attributes and location information.
        @param startX the starting X position of the field
        @param width the width of the field
        @param maxLines the maxLines to display.
        @param provider the highlight provider.
        @return the text field.
        """
        ...

    @staticmethod
    def createSingleLineTextField(factory: ghidra.app.util.viewer.field.FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj, fieldElement: docking.widgets.fieldpanel.field.FieldElement, startX: int, width: int, provider: ghidra.app.util.ListingHighlightProvider) -> ghidra.app.util.viewer.field.ListingTextField:
        """
        Creates a new ListingTextField that displays the text on a single line, clipping as needed.
        @param factory the field factory that generated this field
        @param proxy the object used to populate this field
        @param fieldElement the individual element within the field.
         This holds text, attributes and location information.
        @param startX the starting X position of the field
        @param width the width of the field
        @param provider the highlight provider.
        @return the text field.
        """
        ...

    @staticmethod
    def createSingleLineTextFieldWithReverseClipping(factory: ghidra.app.util.viewer.field.AddressFieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj, fieldElement: docking.widgets.fieldpanel.field.FieldElement, startX: int, width: int, provider: ghidra.app.util.ListingHighlightProvider) -> ghidra.app.util.viewer.field.ListingTextField: ...

    @staticmethod
    def createWordWrappedTextField(factory: ghidra.app.util.viewer.field.FieldFactory, proxy: ghidra.app.util.viewer.proxy.ProxyObj, fieldElement: docking.widgets.fieldpanel.field.FieldElement, startX: int, width: int, maxLines: int, provider: ghidra.app.util.ListingHighlightProvider) -> ghidra.app.util.viewer.field.ListingTextField:
        """
        Displays the given text, word-wrapping as needed to avoid clipping (up to the max number of
         lines.)
        @param factory the field factory that generated this field
        @param proxy the object used to populate this field
        @param fieldElement the individual element within the field.
         This holds text, attributes and location information.
        @param startX the starting X position of the field
        @param width the width of the field
        @param maxLines the maxLines to display.
        @param provider the highlight provider.
        @return the text field.
        """
        ...

    def dataToScreenLocation(self, dataRow: int, dataColumn: int) -> docking.widgets.fieldpanel.support.RowColLocation: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getClickedObject(self, fieldLocation: docking.widgets.fieldpanel.support.FieldLocation) -> object: ...

    def getCol(self, row: int, x: int) -> int: ...

    def getCursorBounds(self, row: int, col: int) -> java.awt.Rectangle: ...

    def getFieldElement(self, screenRow: int, screenColumn: int) -> docking.widgets.fieldpanel.field.FieldElement: ...

    def getFieldFactory(self) -> ghidra.app.util.viewer.field.FieldFactory: ...

    def getHeight(self) -> int: ...

    def getHeightAbove(self) -> int: ...

    def getHeightBelow(self) -> int: ...

    def getNumCols(self, row: int) -> int: ...

    def getNumDataRows(self) -> int: ...

    def getNumRows(self) -> int: ...

    def getPreferredWidth(self) -> int: ...

    def getProxy(self) -> ghidra.app.util.viewer.proxy.ProxyObj: ...

    def getRow(self, y: int) -> int: ...

    def getScrollableUnitIncrement(self, topOfScreen: int, direction: int, max: int) -> int: ...

    def getStartX(self) -> int: ...

    def getText(self) -> unicode: ...

    def getTextWithLineSeparators(self) -> unicode: ...

    def getWidth(self) -> int: ...

    def getX(self, row: int, col: int) -> int: ...

    def getY(self, row: int) -> int: ...

    def hashCode(self) -> int: ...

    def isClipped(self) -> bool: ...

    def isPrimary(self) -> bool: ...

    def isValid(self, row: int, col: int) -> bool: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def paint(self, c: javax.swing.JComponent, g: java.awt.Graphics, context: docking.widgets.fieldpanel.internal.PaintContext, clip: java.awt.Rectangle, map: docking.widgets.fieldpanel.internal.FieldBackgroundColorManager, cursorLoc: docking.widgets.fieldpanel.support.RowColLocation, rowHeight: int) -> None: ...

    def rowHeightChanged(self, heightAbove: int, heightBelow: int) -> None: ...

    def screenLocationToTextOffset(self, row: int, col: int) -> int: ...

    def screenToDataLocation(self, screenRow: int, screenColumn: int) -> docking.widgets.fieldpanel.support.RowColLocation: ...

    def setPrimary(self, b: bool) -> None: ...

    def textOffsetToScreenLocation(self, textOffset: int) -> docking.widgets.fieldpanel.support.RowColLocation: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def clipped(self) -> bool: ...

    @property
    def fieldFactory(self) -> ghidra.app.util.viewer.field.FieldFactory: ...

    @property
    def height(self) -> int: ...

    @property
    def heightAbove(self) -> int: ...

    @property
    def heightBelow(self) -> int: ...

    @property
    def numDataRows(self) -> int: ...

    @property
    def numRows(self) -> int: ...

    @property
    def preferredWidth(self) -> int: ...

    @property
    def primary(self) -> bool: ...

    @primary.setter
    def primary(self, value: bool) -> None: ...

    @property
    def proxy(self) -> ghidra.app.util.viewer.proxy.ProxyObj: ...

    @property
    def startX(self) -> int: ...

    @property
    def text(self) -> unicode: ...

    @property
    def textWithLineSeparators(self) -> unicode: ...

    @property
    def width(self) -> int: ...