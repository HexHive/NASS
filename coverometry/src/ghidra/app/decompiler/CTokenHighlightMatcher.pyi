import ghidra.app.decompiler
import java.awt
import java.lang


class CTokenHighlightMatcher(object):
    """
    The interface that clients must define to create a DecompilerHighlighter
 
     Every function decompiled will trigger this matcher to get called.  The order of method
     calls is: #start(ClangNode), repeated calls to #getTokenHighlight(ClangToken)
     and then #end().
    """









    def end(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getTokenHighlight(self, token: ghidra.app.decompiler.ClangToken) -> java.awt.Color:
        """
        The basic method clients must implement to determine if a token should be highlighted.
         Returning a non-null Color will trigger the given token to be highlighted.
        @param token the token
        @return the highlight color or null
        """
        ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def start(self, root: ghidra.app.decompiler.ClangNode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

