import ghidra.app.util.bin.format.golang.structmapping
import java.lang


class StructureMarkupFunction(object):
    """
    Function that decorates a Ghidra structure
    """









    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def markupStructure(self, context: ghidra.app.util.bin.format.golang.structmapping.StructureContext, markupSession: ghidra.app.util.bin.format.golang.structmapping.MarkupSession) -> None:
        """
        Decorates the specified structure.
        @param context {@link StructureContext}
        @param markupSession state and methods to assist marking up the program
        @throws IOException thrown if error performing the markup
        """
        ...

    def notify(self) -> None: ...

    def notifyAll(self) -> None: ...

    def toString(self) -> unicode: ...

    @overload
    def wait(self) -> None: ...

    @overload
    def wait(self, __a0: long) -> None: ...

    @overload
    def wait(self, __a0: long, __a1: int) -> None: ...

