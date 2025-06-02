import java.lang


class SwiftTypeMetadata(object):
    """
    Parses marks up, and provide access to Swift type metadata
    """





    def __init__(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, log: ghidra.app.util.importer.MessageLog):
        """
        Creates a new {@link SwiftTypeMetadata}
        @param program The {@link Program}
        @param monitor A cancellable task monitor
        @param log The log
        @throws IOException if there was an IO-related error
        @throws CancelledException if the user cancelled the operation
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def markup(self) -> None:
        """
        Marks up this {@link SwiftTypeMetadata} with data structures and comments
        @throws CancelledException if the user cancelled the operation
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

