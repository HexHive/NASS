import ghidra.app.decompiler
import java.lang


class ClangDecompilerHighlighter(object, ghidra.app.decompiler.DecompilerHighlighter):
    """
    The implementation of DecompilerHighlighter.  This will get created by the
     Decompiler and then handed to clients that use the DecompilerHighlightService.  This
     is also used internally for 'secondary highlights'.
 
     This class may be #clone() or #copy(DecompilerPanel) as
     needed when the user creates a snapshot.  Highlight service highlighters will be cloned;
     secondary highlighters will be copied.  Cloning allows this class to delegate highlighting
     and cleanup for clones.  Contrastingly, copying allows the secondary highlights to operate
     independently.
    """









    def applyHighlights(self) -> None: ...

    def clearHighlights(self) -> None: ...

    def dispose(self) -> None: ...

    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def getId(self) -> unicode: ...

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

