import ghidra.app.decompiler
import java.lang


class DecompilerHighlightService(object):
    """
    A service that allows clients to create highlights in the form of background colors for
     ClangTokens in the Decompiler UI.
 
     Note: highlights apply to a full token and not strings of text.  To highlight a token, you
     create an instance of the CTokenHighlightMatcher to pass to one of the
     #createHighlighter(String, CTokenHighlightMatcher) methods of this interface.
 
     There is no limit to the number of highlighters that may be installed.  If multiple
     highlights overlap, then their colors will be blended.
    """









    @overload
    def createHighlighter(self, tm: ghidra.app.decompiler.CTokenHighlightMatcher) -> ghidra.app.decompiler.DecompilerHighlighter:
        """
        Creates a highlighter that will use the given matcher to create highlights as functions
         get decompiled.
        @param tm the matcher
        @return the new highlighter
        """
        ...

    @overload
    def createHighlighter(self, id: unicode, tm: ghidra.app.decompiler.CTokenHighlightMatcher) -> ghidra.app.decompiler.DecompilerHighlighter:
        """
        A version of {@link #createHighlighter(String, CTokenHighlightMatcher)} that allows clients
         to specify an ID.  This ID will be used to ensure that any existing highlighters with that
         ID will be removed before creating a new highlighter.
 
         <p>This method is convenient for scripts, since a script cannot hold on to any created
         highlighters between repeated script executions.   A good value for script writers to use
         is the name of their script class.
        @param id the ID
        @param tm the matcher
        @return the new highlighter
        """
        ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

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

