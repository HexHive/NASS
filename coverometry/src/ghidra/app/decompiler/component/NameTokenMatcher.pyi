import ghidra.app.decompiler
import java.awt
import java.lang


class NameTokenMatcher(object, ghidra.app.decompiler.CTokenHighlightMatcher):
    """
    Matcher used for secondary highlights in the Decompiler.
    """









    def end(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getTokenHighlight(self, token: ghidra.app.decompiler.ClangToken) -> java.awt.Color: ...

    def hashCode(self) -> int: ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def start(self, __a0: ghidra.app.decompiler.ClangNode) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

