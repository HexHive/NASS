import ghidra.app.plugin.languages.sleigh
import java.lang


class SleighSubtableTraversal(object, ghidra.app.plugin.languages.sleigh.VisitorResults):
    """
    A class to traverse SLEIGH constructors in a single table
    """









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

