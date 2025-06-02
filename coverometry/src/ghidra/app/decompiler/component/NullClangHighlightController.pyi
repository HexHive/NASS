from typing import List
import docking.widgets
import docking.widgets.fieldpanel.field
import docking.widgets.fieldpanel.support
import ghidra.app.decompiler
import ghidra.app.decompiler.component
import ghidra.program.model.listing
import java.awt
import java.lang
import java.util
import java.util.function


class NullClangHighlightController(ghidra.app.decompiler.component.ClangHighlightController):
    """
    A stub implementation of the highlight controller that allows clients to avoid null checks
    """





    def __init__(self): ...



    def addBraceHighlight(self, token: ghidra.app.decompiler.ClangSyntaxToken, highlightColor: java.awt.Color) -> None: ...

    def addHighlighter(self, highlighter: ghidra.app.decompiler.component.ClangDecompilerHighlighter) -> None: ...

    def addHighlighterHighlights(self, highlighter: ghidra.app.decompiler.component.ClangDecompilerHighlighter, tokens: java.util.function.Supplier, colorProvider: ghidra.app.decompiler.component.ColorProvider) -> None: ...

    def addListener(self, listener: ghidra.app.decompiler.component.ClangHighlightListener) -> None: ...

    @overload
    def addPrimaryHighlights(self, parentNode: ghidra.app.decompiler.ClangNode, colorProvider: ghidra.app.decompiler.component.ColorProvider) -> None: ...

    @overload
    def addPrimaryHighlights(self, parentNode: ghidra.app.decompiler.ClangNode, ops: java.util.Set, highlightColor: java.awt.Color) -> None: ...

    def addSecondaryHighlighter(self, function: ghidra.program.model.listing.Function, highlighter: ghidra.app.decompiler.component.ClangDecompilerHighlighter) -> None:
        """
        Adds the given secondary highlighter, but does not create any highlights.  All secondary
         highlighters pertain to a given function.
        @param function the function
        @param highlighter the highlighter
        """
        ...

    def blend(self, __a0: List[object]) -> java.awt.Color: ...

    def clearPrimaryHighlights(self) -> None: ...

    def dispose(self) -> None: ...

    @staticmethod
    def dummyIfNull(c: ghidra.app.decompiler.component.ClangHighlightController) -> ghidra.app.decompiler.component.ClangHighlightController: ...

    def equals(self, __a0: object) -> bool: ...

    def fieldLocationChanged(self, location: docking.widgets.fieldpanel.support.FieldLocation, field: docking.widgets.fieldpanel.field.Field, trigger: docking.widgets.EventTrigger) -> None: ...

    def getClass(self) -> java.lang.Class: ...

    def getCombinedColor(self, t: ghidra.app.decompiler.ClangToken) -> java.awt.Color:
        """
        Returns the current highlight color for the given token, based upon all known highlights,
         primary, secondary and highlighters
        @param t the token
        @return the color
        """
        ...

    def getGlobalHighlighters(self) -> java.util.Set:
        """
        Returns all global highlighters installed in this controller.  The global highlighters apply
         to all functions.  This is in contrast to secondary highlighters, which are
         function-specific.
        @return the highlighters
        """
        ...

    def getHighlightedToken(self) -> ghidra.app.decompiler.ClangToken:
        """
        Return the current highlighted token (if exists and unique)
        @return token or null
        """
        ...

    def getHighlighterHighlights(self, highlighter: ghidra.app.decompiler.DecompilerHighlighter) -> ghidra.app.decompiler.component.TokenHighlights:
        """
        Gets all highlights for the given highlighter.
        @param highlighter the highlighter
        @return the highlights
        @see #getPrimaryHighlights()
        """
        ...

    def getPrimaryHighlightedText(self) -> unicode: ...

    def getPrimaryHighlights(self) -> ghidra.app.decompiler.component.TokenHighlights: ...

    def getRandomColorProvider(self) -> ghidra.app.decompiler.component.ColorProvider:
        """
        Returns the color provider used by this class to generate colors.  The initial color
         selection is random.  Repeated calls to get a color for the same token will return the same
         color.
        @return the color provider
        """
        ...

    def getSecondaryHighlight(self, token: ghidra.app.decompiler.ClangToken) -> java.awt.Color: ...

    def getSecondaryHighlightColors(self) -> ghidra.app.decompiler.component.TokenHighlightColors: ...

    def getSecondaryHighlighters(self, function: ghidra.program.model.listing.Function) -> java.util.Set:
        """
        Returns all secondary highlighters for the given function.   This allows clients to update
         the secondary highlight state of a given function without affecting highlights applied to
         other functions.
        @param function the function
        @return the highlighters
        """
        ...

    def getUpdateId(self) -> long:
        """
        An value that is updated every time a new highlight is added.  This allows clients to
         determine if a buffered update request is still valid.
        @return the value
        """
        ...

    def hasPrimaryHighlight(self, token: ghidra.app.decompiler.ClangToken) -> bool: ...

    def hasSecondaryHighlight(self, token: ghidra.app.decompiler.ClangToken) -> bool: ...

    def hasSecondaryHighlights(self, function: ghidra.program.model.listing.Function) -> bool: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def removeHighlighter(self, highlighter: ghidra.app.decompiler.DecompilerHighlighter) -> None: ...

    def removeHighlighterHighlights(self, highlighter: ghidra.app.decompiler.DecompilerHighlighter) -> None:
        """
        Removes all highlights for this highlighter across all functions
        @param highlighter the highlighter
        """
        ...

    def removeListener(self, listener: ghidra.app.decompiler.component.ClangHighlightListener) -> None: ...

    @overload
    def removeSecondaryHighlights(self, token: ghidra.app.decompiler.ClangToken) -> None:
        """
        Removes all secondary highlights for the given token
        @param token the token
        @see #removeSecondaryHighlights(Function)
        """
        ...

    @overload
    def removeSecondaryHighlights(self, f: ghidra.program.model.listing.Function) -> None:
        """
        Removes all secondary highlights for the given function
        @param f the function
        """
        ...

    def toString(self) -> unicode: ...

    def togglePrimaryHighlights(self, hlColor: java.awt.Color, tokens: java.util.function.Supplier) -> None:
        """
        Toggles the primary highlight state of the given set of tokens.  If the given tokens do not
         all have the same highlight state (highlights on or off), then the highlights will be
         cleared.  If all tokens are not highlighted, then they will all become highlighted.
        @param hlColor the highlight color
        @param tokens the tokens
        """
        ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

    @property
    def primaryHighlightedText(self) -> unicode: ...