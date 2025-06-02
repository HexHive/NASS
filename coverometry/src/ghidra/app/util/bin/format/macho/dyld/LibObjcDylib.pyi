import java.lang


class LibObjcDylib(object):
    """
    A class to represent the libobjc DYLIB Mach-O that resides within a DYLD cache
    """





    def __init__(self, libObjcHeader: ghidra.app.util.bin.format.macho.MachHeader, program: ghidra.program.model.listing.Program, space: ghidra.program.model.address.AddressSpace, log: ghidra.app.util.importer.MessageLog, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new {@link LibObjcDylib}
        @param libObjcHeader The libobjc DYLIB header
        @param program The {@link Program}
        @param space The {@link AddressSpace}
        @param log The log
        @param monitor A cancelable task monitor
        @throws IOException if an IO-related error occurred while parsing
        """
        ...



    def equals(self, __a0: object) -> bool: ...

    def getClass(self) -> java.lang.Class: ...

    def hashCode(self) -> int: ...

    def markup(self) -> None:
        """
        Marks up the libobjc DYLIB
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

