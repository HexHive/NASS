import java.lang


class GccAnalysisClass(object):
    """
    An abstract class that can be extended by other classes that perform part of the gcc analysis.
     It provides some basic data types and methods for use by the extending class.
    """

    NEWLINE: unicode = u'\n'



    def __init__(self, monitor: ghidra.util.task.TaskMonitor, program: ghidra.program.model.listing.Program):
        """
        Creates an abstract GccAnalysisClass object. Subclasses should call this constructor
         to initialize the program and task monitor.
        @param monitor task monitor to see if the user has cancelled analysis.
        @param program the program being analyzed.
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

